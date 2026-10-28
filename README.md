
# 🛡️ LinkGuard AI

LinkGuard AI is a cybersecurity awareness application built with
Python, Streamlit, and Google's Gemini API.

## Features

- Suspicious URL structure inspection
- AI-generated explanations of potential link risks
- Optional VirusTotal URL analysis
- Email breach lookup using the XposedOrNot community API
- Shortcuts to Google's official security and device pages

## Technologies

- Python
- Streamlit
- Google Gemini API
- XposedOrNot API
- Optional VirusTotal API

## Installation

1. Install Python 3.10 or newer.
2. Clone or download this repository.
3. Install the dependencies:

   pip install -r requirements.txt

4. Configure your API keys using Streamlit secrets or environment
   variables.
5. Start the app:

   streamlit run app.py

## Configuration

Required:
- GEMINI_API_KEY

Optional:
- GEMINI_MODEL
- VIRUSTOTAL_API_KEY

XposedOrNot email breach checks use its public community API
and do not require an API key.

## Deployment

Upload app.py, requirements.txt, and README.md to GitHub.
Deploy the repository through Streamlit Community Cloud.
Add your Gemini API key under the app's Secrets settings.

## Limitations

- Breach results cover only records available to the data provider.
- No match does not guarantee an email was never exposed.
- AI analysis cannot guarantee a URL is safe.
- Google account information is not accessed directly by this app.
- VirusTotal checks are optional and subject to its own limits.

## Privacy and Security

Never commit API keys or passwords to a public repository.
Do not submit confidential URLs or other sensitive information
to third-party scanning services without permission.

This project is intended for cybersecurity education and awareness.
