import google.generativeai as genai
import os
from dotenv import load_dotenv
import time

# Load the API key securely from the .env file
load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

if API_KEY:
    genai.configure(api_key=API_KEY)

def enhance_findings_with_ai(findings, st_context):
    """
    Takes the static findings and uses an LLM to generate context-aware patches.
    """
    if not API_KEY:
        st_context.error("⚠️ GEMINI_API_KEY not found in .env file. Falling back to static remediation.")
        return findings

    model = genai.GenerativeModel('gemini-1.5-flash')
    enhanced_findings = []
    
    # Create a progress bar in the Streamlit UI so judges see the AI working
    progress_text = "🤖 AI analyzing code context for dynamic remediations..."
    progress_bar = st_context.progress(0, text=progress_text)
    
    for i, f in enumerate(findings):
        prompt = f"""
        You are an expert Mobile DevSecOps Engineer. 
        A static analysis tool found this vulnerability in an Android APK:
        - Vulnerability: {f['title']}
        - Details: {f['description']}
        - Standard Advice: {f['remediation']}
        
        Write a highly technical, context-aware 2-sentence patch recommendation for an Android developer.
        Focus on actual code implementations or manifest configurations. Do not use markdown formatting.
        """
        
        try:
            # Call the AI model
            response = model.generate_content(prompt)
            # Overwrite the static remediation with the AI response
            f['remediation'] = f"🤖 AI Context-Patch: {response.text.strip()}"
        except Exception as e:
            # If the API fails, it gracefully falls back to your static advice
            pass 
            
        enhanced_findings.append(f)
        
        # Update UI progress bar
        progress_bar.progress((i + 1) / len(findings), text=progress_text)
        time.sleep(0.5) # Prevent hitting API rate limits
        
    # Clear the progress bar when done
    progress_bar.empty()
    return enhanced_findings