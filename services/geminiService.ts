
import { GoogleGenAI, Type } from "@google/genai";
import { SYSTEM_INSTRUCTION } from "../constants.ts";
import { AIAnalysisResponse } from "../types.ts";

export const analyzeSecurityFindings = async (findings: any): Promise<AIAnalysisResponse> => {
  const ai = new GoogleGenAI({ apiKey: process.env.API_KEY || '' });
  
  const prompt = `Analyze the following simulated security scan results and provide an educational report:
  ${JSON.stringify(findings, null, 2)}
  
  For each vulnerability, you MUST provide:
  1. A real-world URL to an exploit (Exploit-DB, GitHub, or CVE details).
  2. Step-by-step instructions on how the exploitation process works.
  3. Analysis of the discovered directories and if any sensitive files were exposed.
  
  Focus on identifying CVEs, explaining exploit theory, and suggesting remediations.`;

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
          recommendations: {
            type: Type.ARRAY,
            items: { type: Type.STRING }
          },
          exploitPaths: {
            type: Type.ARRAY,
            items: { type: Type.STRING }
          }
        },
        required: ["summary", "riskScore", "recommendations", "exploitPaths"]
      }
    }
  });

  try {
    return JSON.parse(response.text || '{}');
  } catch (e) {
    console.error("Failed to parse Gemini response", e);
    return {
      summary: "Error generating analysis.",
      riskScore: 0,
      recommendations: [],
      exploitPaths: []
    };
  }
};
