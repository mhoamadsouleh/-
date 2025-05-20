
import os, time, subprocess, shutil, requests
from flask import Flask, request, redirect, render_template, send_from_directory, url_for, flash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'secret'
UPLOAD_FOLDER = "./uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
API_KEY = '2ec241972ed224405090681092436f106705ac33be3cd3b94d09d2725581891b'
headers = {"x-apikey": API_KEY}
url_scan = "https://www.virustotal.com/api/v3/files"
url_report = "https://www.virustotal.com/api/v3/analyses/"
uploaded_files = {}

def scan(file_path):
    try:
        with open(file_path, 'rb') as f:
            response = requests.post(url_scan, headers=headers, files={'file': f})
        if response.status_code == 200:
            scan_id = response.json()['data']['id']
            time.sleep(20)
            result = requests.get(f"{url_report}{scan_id}", headers=headers).json()
            stats = result['data']['attributes']['stats']
            return stats['malicious'] == 0
    except Exception as e:
        print(f"Scan error: {e}")
    return False

@app.route('/')
def index():
    return render_template("index.html", files=uploaded_files)

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    if file and file.filename.endswith('.py'):
        path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(path)
        if scan(path):
            uploaded_files[file.filename] = {
                "path": path,
                "status": "uploaded"
            }
            flash("تم رفع الملف بنجاح", "success")
        else:
            os.remove(path)
            flash("⚠️ الملف يحتوي على أكواد ضارة!", "danger")
    else:
        flash("فقط ملفات .py مسموحة", "warning")
    return redirect(url_for('index'))

@app.route('/run/<filename>')
def run_file(filename):
    file_data = uploaded_files.get(filename)
    if file_data:
        try:
            process = subprocess.Popen(["python3", file_data["path"]])
            file_data["status"] = "running"
            file_data["process"] = process
            flash(f"تم تشغيل الملف {filename}", "success")
        except Exception as e:
            flash(f"خطأ في التشغيل: {e}", "danger")
    return redirect(url_for('index'))

@app.route('/stop/<filename>')
def stop_file(filename):
    file_data = uploaded_files.get(filename)
    if file_data and "process" in file_data:
        process = file_data["process"]
        process.terminate()
        file_data["status"] = "stopped"
        flash(f"تم توقيف الملف {filename}", "info")
    return redirect(url_for('index'))

@app.route('/delete/<filename>')
def delete_file(filename):
    file_data = uploaded_files.pop(filename, None)
    if file_data:
        os.remove(file_data["path"])
        flash(f"تم حذف الملف {filename}", "danger")
    return redirect(url_for('index'))

@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
