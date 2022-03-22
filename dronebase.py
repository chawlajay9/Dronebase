from colorama import Fore, init, Back
import getpass
import os
import json
from cv2 import log
import requests
import hashlib
from datetime import datetime

# init colors
init(autoreset=True)

# Create empty directory as Database and load the content og "git.db" if it exists
DATABASE = {}

if os.path.isfile("user.json"):
    DATABASE = dict(
        json.load(
            open("user.json", "r")
        )
    )


def dump():
    """
    This function writes the contents of our DATABASE to a file using json
    so that it can be read later
    """
    try:
        json.dump(DATABASE, open("user.json", "w"), indent=4)
    except Exception as e:
        print("Could not save database: ", e)


def login():
    """
    Check for user credentials and if right then display weather dashboard.
    """
    email = input(f"{Fore.BLUE}EMAIL:")
    if not email:
        print(f"{Back.RED}Please enter EMAIL")
        login()
        exit()
    password = getpass.getpass(f"{Fore.BLUE}PASSWORD:")
    if not password:
        print(f"{Back.RED}Please enter password")
        login()
        exit()
    if os.path.exists("user.json"):
        db_user = DATABASE.get(email, False)
        if db_user:
            db_password = db_user.get("password", False)
            password = get_hash(password)
            if db_password and db_password == password:
                print(f"{Back.GREEN}LOGIN Succesfully.")
                print()
                dashboard()
            else:
                print(f"{Back.RED}You have entered wrong password")
                login()
        else:
            print(f"{Back.RED}User Doesnot exist. Please Register")
            login()
    else:
        print(f"{Back.RED}User Doesnot exist. Please Register")
        main()


def register():
    """
    Register user detials.
    """
    username = input(f"{Fore.BLUE}USERNAME:")
    if not username:
        print(f"{Back.RED}Please enter username")
        register()
        exit()
    email = input(f"{Fore.BLUE}EMAIL:")
    if not email:
        print(f"{Back.RED}Please enter email")
        register()
        exit()
    password = getpass.getpass(f"{Fore.BLUE}PASSWORD:")
    if not password:
        print(f"{Back.RED}Please enter password")
        register()
        exit()
    db_user = DATABASE.get(email, False)
    if db_user:
        print(f"{Back.RED}User with same email already exist.")
        print()
        register()
    else:
        password = get_hash(password)
        user_data = {
            "username": username,
            "password": password,
        }
        DATABASE[email] = user_data
        dump()
        print(f"{Back.GREEN} {email.upper()} Registered Succesfully.")
        print(f"{Fore.GREEN} Please LOGIN.")
        main()


def dashboard():
    """
    Take API key, latitude, longitude & date as input and display weather forecast.
    """
    api_key = getpass.getpass(f"{Fore.BLUE}Enter API KEY:")
    if not api_key:
        print(f"{Back.RED}Please enter API KEY")
        dashboard()
        exit()
    try:
        lat = float(input(f"{Fore.BLUE}Enter latitude:"))
        if not lat or lat < -90 or lat > 90:
            print(f"{Back.RED} Invalid latitude")
            dashboard()
            exit()
        lon = float(input(f"{Fore.BLUE}Enter longitude:"))
        if not lon or lon < -180 or lon > 180:
            print(f"{Back.RED} Invalid longitude")
            dashboard()
            exit()
    except ValueError:
        print(f"{Back.RED}Please enter a float value")
        dashboard()
        exit()

    url = "https://api.openweathermap.org/data/2.5/onecall"
    parameters = {
        "lat": lat,
        "lon": lon,
        "appid": api_key
    }
    try:
        response = requests.get(url, params=parameters, timeout=5)
        response.raise_for_status()
    except response.status_code == 401:
        print(f"{Back.RED}Invalid API key")
    except Exception as exc:
        print(f"{Back.RED}{exc.with_traceback()}")
    if response:
        print(f"{Back.YELLOW}{Fore.BLACK}WEATHER FORECATE")
        response = response.json()
        current_data = response.get("current")
        print(f"{Fore.BLUE} Humidity:{current_data.get('humidity')}")
        print(f"{Fore.BLUE} Pressure:{current_data.get('pressure')}")
        print(f"{Fore.BLUE} Average temperature:{current_data.get('temp')}")
        print(f"{Fore.BLUE} Wind Speed:{current_data.get('wind_speed')}")
        print(f"{Fore.BLUE} Wind degree:{current_data.get('wind_deg')}")
        print(f"{Fore.BLUE} UV Index:{current_data.get('uvi')}")

        alerts = response.get("alerts", False)
        if alerts:
            for alert in alerts:
                print(f"{Fore.RED} Events: {alert.get('events')}")
                start_time = datetime.datetime.fromtimestamp(
                    alert.get("start"))
                print(f"{Fore.RED}Start Time: {start_time}")
                end_time = datetime.datetime.fromtimestamp(alert.get("end"))
                print(f"{Fore.RED}End Time: {end_time}")
                print(f"{Fore.RED} Description: {alert.get('description')}")


def get_hash(password):
    """
    Generated hash of plaintext and return it.
    """
    if not password:
        raise ValueError("Password is empty")
    digest = hashlib.sha256(password.encode())
    hash = digest.hexdigest()
    return hash


def main():
    """
    Program main panel.
    """
    print(f"{Fore.BLUE}1. Login")
    print(f"{Fore.BLUE}2. Register")
    print(f"{Fore.BLUE}3. Quit")
    choice = input(f"{Fore.BLUE}Enter your choice:")
    if not choice or len(choice) > 1:
        print(f"{Back.RED}Invalid input")
        main()
    if choice == "1":
        login()
    elif choice == "2":
        register()
    elif choice == "3":
        exit()
    else:
        print(f"{Back.RED}You have entered wrong input")
        main()


if __name__ == "__main__":
    main()
