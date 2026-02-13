
import { GoogleGenAI, Type } from "@google/genai";
import { SYSTEM_INSTRUCTION } from "../constants.ts";
import { AIAnalysisResponse } from "../types.ts";

export const analyzeSecurityFindings = async (findings: any): Promise<AIAnalysisResponse> => {
  // Use correct initialization from environment variable as per guidelines
  const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
  
  const prompt = `Simulated Date: 2026-02-13.
  Analyze the following security scan results from ANACONDA.
  Findings: ${JSON.stringify(findings, null, 2)}
  
  Tasks:
  1. Determine if these vulnerabilities are mitigated in a standard 2026 environment.
  2. Provide a "Trace Risk" score based on the user's stealth settings (MAC spoofing, timing, etc.).
  3. Suggest ways to further obfuscate the source of the attack to make attribution impossible.
  4. List 2026-relevant exploit paths.`;

  const response = await ai.models.generateContent({
    model: 'gemini-3-flash-preview',
    contents: prompt,
    config: {
      systemInstruction: SYSTEM_INSTRUCTION,
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          summary: { type: Type.STRING },
          riskScore: { type: Type.NUMBER },
          traceRisk: { type: Type.NUMBER, description: "Likelihood of attribution/detection (0-100)" },
          recommendations: {
            type: Type.ARRAY,
            items: { type: Type.STRING }
          },
          exploitPaths: {
            type: Type.ARRAY,
            items: { type: Type.STRING }
          }
        },
        required: ["summary", "riskScore", "traceRisk", "recommendations", "exploitPaths"]
      }
    }
  });

  try {
    // Access text property directly as per guidelines
    const text = response.text;
    return JSON.parse(text || '{}');
  } catch (e) {
    console.error("Failed to parse Gemini response", e);
    return {
      summary: "Error generating 2026 analysis report.",
      riskScore: 0,
      traceRisk: 100,
      recommendations: ["Check API Key", "Verify Network Connectivity"],
      exploitPaths: []
    };
  }
};
