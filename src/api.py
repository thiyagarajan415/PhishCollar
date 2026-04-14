from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

# (Keep your other imports and app initialization here)

# Mount the static directory so the server can see your HTML/CSS
app.mount("/static", StaticFiles(directory="src/static"), name="static")

# Create a route for the homepage
@app.get("/")
def read_root():
    return FileResponse("src/static/index.html")


from fastapi import FastAPI, HTTPException

from feature_extractor import URLFeatureExtractor
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pandas as pd
import os
import shap

app = FastAPI(title="Phishing Detection API")

# Allow Frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load Models
if os.path.exists('models/optimized_meta_ensemble.pkl'):
    base_path = 'models/'
elif os.path.exists('../models/optimized_meta_ensemble.pkl'):
    base_path = '../models/'
else:
    base_path = None

try:
    if base_path:
        model = joblib.load(base_path + 'optimized_meta_ensemble.pkl')
        optimal_features = joblib.load(base_path + 'optimal_features_list.pkl')
        print(f"✅ Models loaded successfully from: {base_path}")
except Exception as e:
    model, optimal_features = None, []
    print(f"❌ Error loading models: {e}")

class URLRequest(BaseModel):
    url: str

@app.post("/predict")
def predict(data: URLRequest):
    try:
        # 1. Extract Real-Time Features
        extractor = URLFeatureExtractor(data.url)
        extracted_features_dict = extractor.extract()
        
        final_array = []
        for feature_name in optimal_features:
            val = extracted_features_dict.get(feature_name.strip(), 0)
            final_array.append(val)
            
        df = pd.DataFrame([final_array], columns=optimal_features)
        
        # 2. Get the Final Prediction from the Stacking Classifier
        prediction_result = int(model.predict(df)[0])
        result_text = "Phishing" if prediction_result == -1 else "Legitimate"
        
        # 3. EXPLAINABLE AI (SHAP) LOGIC
        threat_indicators = []
        if prediction_result == 0: 
            # Extract XGBoost from the Stacking Classifier for explanations
            xgb_model = model.named_estimators_['XGBoost']
            
            explainer = shap.TreeExplainer(xgb_model)
            shap_values = explainer.shap_values(df)
            
            # Handle different SHAP output formats
            if isinstance(shap_values, list):
                instance_shap = shap_values[1][0] 
            else:
                instance_shap = shap_values[0]
            
            # Match SHAP values to feature names
            feature_impacts = list(zip(optimal_features, instance_shap, final_array))
            
            # Sort ascending so the most NEGATIVE SHAP values (Phishing indicators) are first
            feature_impacts.sort(key=lambda x: x[1])
            
            explanation_map = {
                'having_IPhaving_IP_Address': 'IP address used instead of a domain name.',
                'URLURL_Length': 'Unusually long or obfuscated URL.',
                'Prefix_Suffix': 'Suspicious use of dashes (-) in the domain name.',
                'having_Sub_Domain': 'Excessive subdomains detected (e.g., a.b.c.com).',
                'SSLfinal_State': 'Missing or invalid HTTPS/SSL certificate.',
                'HTTPS_token': 'Deceptive use of "https" within the domain name itself.',
                'age_of_domain': 'Domain was registered very recently or lookup failed.',
                'Redirect': 'Suspicious number of page redirects.',
                'URL_of_Anchor': 'High percentage of links point to external or dead pages.',
                'Links_in_tags': 'Scripts and metadata load from untrusted external sources.',
                'Submitting_to_email': 'Page attempts to silently submit data to an email address.',
                'on_mouseover': 'Malicious JavaScript detected hiding the status bar.'
            }
            
            # Grab the top 3 most impactful reasons
            for feature, shap_val, actual_val in feature_impacts:
                
                # THE FIX: Strip the sneaky trailing spaces from the Kaggle dataset!
                clean_feature = feature.strip()
                
                # Check for negative SHAP value and a suspicious/neutral feature value (< 1)
                if shap_val < 0 and clean_feature in explanation_map and actual_val < 1:
                    threat_indicators.append(explanation_map[clean_feature])
                if len(threat_indicators) >= 3:
                    break
                    
            if not threat_indicators:
                threat_indicators = ["General structural anomalies detected by the AI ensemble."]

        return {
            "prediction_code": prediction_result,
            "status": result_text,
            "model_used": "5-Model Titan Meta-Ensemble",
            "threat_indicators": threat_indicators
        }
    except Exception as e:
        return {"error_message": f"Prediction failed: {str(e)}"}