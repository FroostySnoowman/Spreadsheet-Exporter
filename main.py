import os
import asyncio
import pathlib
import yaml
from gsheets import Sheets
from flask import Flask, send_file
from threading import Thread

app = Flask(__name__)

def load_config():
    config_path = f'{pathlib.Path(__file__).parent.absolute()}/config.yml'
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, 'r') as file:
        data = yaml.safe_load(file)
    return data

config = load_config()

async def export_spreadsheet():
    print("Exporting spreadsheet...")
    sheets = Sheets.from_files(f'{pathlib.Path(__file__).parent.absolute()}/{config["Google"]["GOOGLE_CLIENT_SECRET_FILE_NAME"]}')
    spreadsheet = sheets[config["Google"]["GOOGLE_SPREADSHEET_ID"]]
    sheet = spreadsheet.sheets[0]

    df = sheet.to_frame(header=None).reset_index(drop=True)
    df.columns = [str(i+1) for i in range(df.shape[1])]

    export_mode = config["General"]["ExportMode"]
    file_path = None

    if export_mode == "single_column":
        column_name = config["General"].get("ColumnName", "")
        file_path = f'{pathlib.Path(__file__).parent.absolute()}/{config["General"]["TXT_FILE_NAME"]}'

        if column_name in df.columns:
            df[column_name].astype(str).to_csv(file_path, index=False, header=False)
            print(f"Exported single column '{column_name}' to {file_path}")
        else:
            print(f"Error: Column '{column_name}' not found in spreadsheet.")
            return None

    elif export_mode == "full_spreadsheet":
        export_format = config["General"].get("ExportFormat", "csv").lower()
        file_path = f'{pathlib.Path(__file__).parent.absolute()}/{config["General"]["FILE_NAME"]}'

        if export_format == "csv":
            df.to_csv(file_path, sep='\t', index=False)
            print(f"Exported full spreadsheet to {file_path} as CSV.")
        elif export_format == "xlsx":
            df.to_excel(file_path, index=False)
            print(f"Exported full spreadsheet to {file_path} as XLSX.")
        else:
            print(f"Error: Unsupported export format '{export_format}'.")
            return None

    if not os.path.exists(file_path):
        print(f"File was not created: {file_path}")
    return file_path

async def initial_export():
    file_path = await export_spreadsheet()
    if file_path and os.path.exists(file_path):
        print(f"Initial file ready: {file_path}")
    else:
        print("Initial export failed.")

async def run_every_hour():
    while True:
        await export_spreadsheet()
        await asyncio.sleep(3600)

def start_asyncio_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(run_every_hour())

thread = Thread(target=start_asyncio_loop)
thread.daemon = True
thread.start()

@app.route('/download', methods=['GET'])
def download_latest_file():
    export_format = config["General"].get("ExportFormat", "csv").lower()
    file_name = config["General"]["TXT_FILE_NAME"] if export_format == "csv" else config["General"]["FILE_NAME"]
    file_path = f'{pathlib.Path(__file__).parent.absolute()}/{file_name}'

    print(f"Attempting to serve file: {file_path}")

    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "No exported file available yet.", 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=config["General"]["WEBSERVER_PORT"], threaded=True)