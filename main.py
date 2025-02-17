from fastapi import FastAPI, File, UploadFile
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import json
import uvicorn
from configCheck import scan_config

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    if file.content_type != "application/json":
        return {"error": "Invalid file type. Only JSON files are accepted."}
    
    contents = await file.read()
    try:
        json_contents = json.loads(contents)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON file."}
    
    issues = scan_config(contents)
    if issues:
        # Convert issues to JSON format and print
        issues_dict = [{"severity": issue.severity, 
                        "category": issue.category,
                        "resource": issue.resource,
                        "message": issue.message} for issue in issues]
        print("\nJSON Output:")
        severity_order = {"HIGH": 1, "MEDIUM": 2, "LOW": 3}
        issues_dict.sort(key=lambda x: severity_order.get(x["severity"], 4))
        results = json.dumps(issues_dict, indent=2)
        # print(results)

    else:
        results = "No security issues detected"

    return {"filename": file.filename, "results": results, "status": "file analyzed"}


# Mount the /static directory
app.mount("/", StaticFiles(directory="static", html=True), name="static")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)