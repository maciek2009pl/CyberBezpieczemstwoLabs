import os
from getpass import getpass

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait


url = "https://localhost:7003/Identity/Account/Login"
username = "maciek13"
password = "12345POP.d"

browser = webdriver.Chrome()

try:
    browser.get(url)
    WebDriverWait(browser, 10).until(
        lambda driver: driver.find_element(By.NAME, "Input.Login")
    ).send_keys(username)
    browser.find_element(By.NAME, "Input.Password").send_keys(password)
    input("Enter")
finally:
    browser.quit()