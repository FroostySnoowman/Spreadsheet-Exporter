# PekoSodies Spreadsheet Exporter and Uploader Script

## General Setup
First, install Python 3.X and the required libraries through `pip install -r requirements.txt`.

## Config
The config is designed to be as user friendly as possible, allowing for everything to be configurable.

First, rename the `example_config.yml` file to `config.yml`.

```yml
General:
    FILE_NAME: ""
```
This is the file name of the file. This name will be displayed in dropbox. You must keep the same filename here as in `DROPBOX_FILE_PATH`.

```yml
Google:
    GOOGLE_CLIENT_SECRET_FILE_NAME: ""
```
Google requires a client secret FILE. This is the name of that file (filepath). To retrieve this, you need to go to https://console.cloud.google.com/welcome?organizationId=0. From here, click the dropdown towards the top left of your screen and choose "New Project" in the top right. Feel free to name this whatever you want. After it is created, make sure it is selected on the top left of your screen and choose "APIs & Services". Click on "ENABLE APIS AND SERVICES". Search for "Google Drive API", click on it, and enable it. You will also need to search for "Google Sheets API" and enable it. Now, you can go back to the Project Details and click on "Credentials". From here, click on "CREATE CREDENTIALS", "OAuth client ID", "CONFIGURE CONSENT SCREEN", "External", name it anything you want, add your gmail as the "User support email" and "Developer contact information" and click "SAVE AND CONTINUE". Click "ADD OR REMOVE SCOPES", click the box next to "API" and "UPDATE" and "SAVE AND CONTINUE". Click "ADD USERS" and add your gmail account there and "SAVE AND CONTINUE" and "BACK TO DASHBOARD". From here, go back to "Credentials" and click on "CREATE CREDENTIALS" and "OAuth client ID", choose "Desktop App" and name it whatever you want and "CREATE". Next, download the JSON file and put it in the same folder main.py is located and update the GOOGLE_CLIENT_SECRET_FILE_NAME with that file name, including .json (client_secret.json).

```yml
Google:
    GOOGLE_SPREADSHEET_ID: ""
```
This step is much more simple. You need to simply get the ID to your spreadsheet which is found in the URL of that spreadsheet. Example URL: `https://docs.google.com/spreadsheets/d/1KU8TXn5QYtZnQxEBIzI41QygNKrehviEoBbmQ8dOFIs/edit#gid=0` Example ID: `1KU8TXn5QYtZnQxEBIzI41QygNKrehviEoBbmQ8dOFIs`.