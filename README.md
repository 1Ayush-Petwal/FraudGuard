# FraudGuard:

FraudGuard is an **AI-powered Chrome browser extension** designed to detect and warn users about **fraudulent or cloned bank and payment websites** in real time.

The extension continuously monitors the active browser tab and extracts the website URL. This URL is sent to a backend fraud-detection service, where multiple signals are analyzed, including **URL similarity with official bank domains, domain age, HTTPS/SSL presence, and keyword patterns commonly used in phishing sites**.

A hybrid detection approach is used, combining **rule-based heuristics** with **AI-generated risk analysis**, to produce a **fraud risk score (0–100)** along with an explainable reason set. If the risk exceeds a predefined threshold, the extension injects a **high-priority warning popup** directly into the webpage.

The popup provides:

- Risk classification (Safe / Suspicious / Dangerous)
- Fraud score and reasoning
- User actions (exit site, report fraud, continue)

The MVP is implemented as a **Chrome Extension (Manifest v3)** using JavaScript for content and background scripts, with a **Python (FastAPI) backend** deployed on Azure. Optional integration with **Azure OpenAI** is used to generate human-readable explanations for detected threats.

The system is designed to be lightweight, scalable, and extensible, with future support for SMS link scanning, community-driven fraud intelligence, and bank/fintech API integration.

## Resources to Refer

Below are the main resources I’ll use to build and understand the FraudGuard project. These are focused only on what’s needed for the MVP and the Imagine Cup timeline.

---

### Chrome Browser Extension (Core Requirement)

I’ll refer to the official Chrome Extensions documentation to understand how browser extensions work, especially content scripts and Manifest V3.

- Chrome Extensions Docs:
    
    https://developer.chrome.com/docs/extensions/
    

Main topics to focus on:

- Manifest V3
- Content scripts
- Background service workers
- Injecting UI elements (popups) into webpages

I’ll also look at beginner tutorials and examples on how to build simple Chrome extensions using JavaScript.

---

### URL & Phishing Detection Logic

To detect fake or cloned bank websites, I’ll refer to resources related to URL similarity and phishing detection.

- Python `difflib` (SequenceMatcher) for URL similarity comparison
    
    https://docs.python.org/3/library/difflib.html
    

I’ll also study common characteristics of phishing and fake banking websites, such as:

- Typosquatted domains
- Recently created domains
- Use of keywords like “secure”, “login”, or “verify”

---

### Backend API (FastAPI)

For the backend fraud detection service, I’ll use FastAPI because it is lightweight and ideal for hackathons.

- FastAPI Documentation:
    
    https://fastapi.tiangolo.com/
    

Key topics:

- Creating REST APIs
- Handling JSON requests
- Running APIs locally with Uvicorn

---

### AI & Explainable Output (Optional Enhancement)

To generate human-readable fraud explanations, I’ll refer to Azure OpenAI resources.

- Azure OpenAI Documentation:
    
    https://learn.microsoft.com/en-us/azure/ai-services/openai/
    

This will be used to convert technical fraud signals into simple explanations that users can understand.

---

### Microsoft Azure (Hackathon Alignment)

Since this is a Microsoft Imagine Cup project, I’ll use Microsoft Learn to understand basic Azure deployment.

- Microsoft Learn:
    
    https://learn.microsoft.com/
    

Topics to search:

- Deploying Python apps on Azure
- Azure App Service basics
- AI solutions with Azure

---

### UI & Popup Design

For the warning popup UI, I’ll refer to basic CSS and browser notification design patterns.

Focus areas:

- Fixed-position popups
- Z-index and overlays
- Clean, minimal warning UI

I’ll also take inspiration from:

- Truecaller spam warnings
- Browser security alert designs

---

### Sample Phishing URLs (For Demo Only)

For testing and demo purposes, I’ll use publicly available phishing URL examples.

Search topics:

- Phishing URL datasets
- Fake banking website examples

Only a small set of sample URLs is needed for demonstration.

---

### Imagine Cup References

To align the project with Imagine Cup expectations, I’ll refer to:

- Imagine Cup Official Website:
    
    https://imaginecup.microsoft.com/
    

I’ll mainly focus on understanding:

- How past teams explain their ideas
- How MVPs are demonstrated
- How impact and AI usage are presented

---

### Priority Order (Time-Bound)

Since time is limited, I’ll prioritize resources in this order:

1. Chrome extension basics
2. URL similarity and phishing detection
3. Popup warning UI
4. Backend API integration
5. Azure deployment (if time allows)