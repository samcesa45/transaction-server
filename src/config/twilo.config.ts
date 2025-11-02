export default () => ({
    twilio: {
       twilioAccountSid: process.env.TWILIO_ACCOUNT_SID, 
       twilioAuthToken: process.env.TWILIO_AUTH_TOKEN,
       twilioVerifySid: process.env.TWILIO_VERIFY_SERVICE_SID,
       twilioPhoneNumber: process.env.TWILIO_PHONE_NUMBER
    }
})