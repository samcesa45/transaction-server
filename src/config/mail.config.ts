export default () => ({
  mail: {
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    secure: process.env.SMTP_SECURE === 'true',
    from: process.env.MAIL_FROM,
  },
});
