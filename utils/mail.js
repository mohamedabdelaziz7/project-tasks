require('dotenv').config();
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_ADDRESS, 
    pass: process.env.GMAIL_PASSWORD 
  },
});

async function main() {
  
  const verificationCode = Math.floor(100000 + Math.random() * 900000);

 
  const info = await transporter.sendMail({
    from:  `"Your Name" <${process.env.EMAIL_ADDRESS}>`,
    to: "recipient@example.com", 
    subject: "Verification Code", 
    text: `Your verification code is: ${verificationCode}`, 
  });

  console.log("Message sent: %s", info.messageId);
}

main().catch(console.error);

