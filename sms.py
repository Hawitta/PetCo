from twilio.rest import Client
from dotenv import load_dotenv
import os

load_dotenv()

phone_number = os.getenv("PHONE_NUMBER")
account_sid = os.getenv("TWILIO_ACCOUNT_SID")
auth_token = os.getenv("TWILIO_AUTH_TOKEN")
verify_sid = os.getenv("VERIFY_SID")

client = Client(account_sid, auth_token)

otp_verification = client.verify.services(verify_sid).verifications.create(
    to=phone_number, channel="sms"
)

print(otp_verification.status)
otp_code = input("Please enter OTP: ")


otp_vcheck = client.verify.services(verify_sid).verfication.check.create(
    to =phone_number, code=otp_code
)

print(otp_vcheck.status)