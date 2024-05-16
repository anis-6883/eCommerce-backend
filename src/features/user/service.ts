import nodemailer from "nodemailer";

export const sendVerificationEmail = async (email: string, verificationCode: number) => {
  const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
      user: process.env.MAIL_USERNAME,
      pass: process.env.MAIL_PASSWORD,
    },
  });

  const mailOptions = {
    from: process.env.MAIL_USERNAME,
    to: email,
    subject: "Email Verification",
    html: `
    <body style="-moz-box-sizing:border-box;-ms-text-size-adjust:100%;-webkit-box-sizing:border-box;-webkit-text-size-adjust:100%;Margin:0;background:#f5f5f5;background-color:#f3f4f8;box-sizing:border-box;color:#0a0a0a;font-family:Helvetica,Arial,sans-serif;font-size:14px;font-weight:400;line-height:1.43;margin:0;min-width:600px;padding:0;text-align:left;width:100%!important">
    <table class="miro__container" align="center" width="600" cellpadding="0" cellspacing="0" style="border-collapse:collapse;border-spacing:0;font-family:Helvetica,Arial,sans-serif;max-width:600px;min-width:600px;padding:0;text-align:left;vertical-align:top">
      <tr style="font-family:Helvetica,Arial,sans-serif;padding:0;text-align:left;vertical-align:top">
        <td class="miro__content-wrapper" style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;border-collapse:collapse!important;color:#0a0a0a;font-family:Helvetica,Arial,sans-serif;font-size:14px;font-weight:400;hyphens:auto;line-height:1.43;margin:0;padding:0;padding-top:43px;text-align:left;vertical-align:top;word-wrap:break-word">
          <div class="miro__content" style="background-color:#fff;font-family:Helvetica,Arial,sans-serif">
            <div class="miro__header" style="font-family:Helvetica,Arial,sans-serif;height:100%;min-height:100px;padding:0 40px">
              <table class="miro__header-content" style="border-collapse:collapse;border-spacing:0;font-family:Helvetica,Arial,sans-serif;padding:0;text-align:left;vertical-align:top;width:100%">
                <tr style="font-family:Helvetica,Arial,sans-serif;padding:0;text-align:left;vertical-align:top">
                  <td class="miro__col-header-logo" style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;border-collapse:collapse!important;color:#0a0a0a;font-family:Helvetica,Arial,sans-serif;font-size:14px;font-weight:400;hyphens:auto;line-height:1.43;margin:0;padding:0;padding-top:32px;text-align:left;vertical-align:top;width:50%;word-wrap:break-word">
                    <a href="/" target="_blank" style="Margin:0;color:#2a79ff;font-family:Helvetica,Arial,sans-serif;font-weight:400;line-height:1.43;margin:0;padding:0;text-align:left;text-decoration:none">
                      <img src="https://rtb-production-eu-mail.s3.eu-west-1.amazonaws.com/miro/images/logo.png" style="-ms-interpolation-mode:bicubic;border:none;clear:both;display:block;font-family:Helvetica,Arial,sans-serif;height:30px;max-height:100%;max-width:100%;outline:0;text-decoration:none;width:auto">
                    </a>
                  </td>
                </tr>
              </table>
            </div>
            <div class="miro__content-body" style="font-family:Helvetica,Arial,sans-serif">
              <div class="miro-title-block" style="background-position:center;background-repeat:no-repeat;background-size:100% auto;font-family:Helvetica,Arial,sans-serif;padding:40px 40px 36px">
                <div class="miro-title-block__title font-size-42" style="color:#050038;font-family:Helvetica,Arial,sans-serif;font-size:42px!important;font-stretch:normal;font-style:normal;font-weight:700;letter-spacing:normal;line-height:1.24">Email Verification</div>
                <div class="miro-title-block__subtitle font-size-20 m-top-16" style="color:#050038;font-family:Helvetica,Arial,sans-serif;font-size:20px!important;font-stretch:normal;font-style:normal;font-weight:400;letter-spacing:normal;line-height:1.4;margin-top:16px;opacity:.6">Please use the following verification code to complete your registration:</div>
              </div>
              <div class="miro-confirmation-code-block" style="font-family:Helvetica,Arial,sans-serif;padding:0 40px">
                <div class="miro-confirmation-code-block__code" style="background-color:#f3f4f8;border-radius:4px;color:#050038;font-family:Helvetica,Arial,sans-serif;font-size:48px;font-stretch:normal;font-style:normal;font-weight:700;height:128px;letter-spacing:normal;line-height:128px;text-align:center">${verificationCode}</div>
              </div>
              <div class="miro-title-block" style="background-position:center;background-repeat:no-repeat;background-size:100% auto;font-family:Helvetica,Arial,sans-serif;padding:10px 0 0 40px">
                <div class="miro-title-block__title font-size-42" style="color:#050038;font-family:Helvetica,Arial,sans-serif;font-size:42px!important;font-stretch:normal;font-style:normal;font-weight:700;letter-spacing:normal;line-height:1.24"></div>
                <p class="font-size-20 m-top-16" style="color:#050038;font-family:Helvetica,Arial,sans-serif;font-size:16px!important;font-stretch:normal;font-style:normal;font-weight:400;letter-spacing:normal;line-height:1.4;margin-top:16px;opacity:.6">Don't share your otp with anyone!</p>
                <p class="font-size-20 m-top-16" style="color:#050038;font-family:Helvetica,Arial,sans-serif;font-size:16px!important;font-stretch:normal;font-style:normal;font-weight:400;letter-spacing:normal;line-height:1.4;margin-top:16px;opacity:.6">Thank you for signing up!</p>
                <p class="font-size-20 m-top-16" style="color:#050038;font-family:Helvetica,Arial,sans-serif;font-size:16px!important;font-stretch:normal;font-style:normal;font-weight:400;letter-spacing:normal;line-height:1.4;margin-top:16px;opacity:.6">Best Regards,</p>
                <p class="font-size-20 m-top-16" style="color:#050038;font-family:Helvetica,Arial,sans-serif;font-size:16px!important;font-stretch:normal;font-style:normal;font-weight:400;letter-spacing:normal;line-height:1.4;margin-top:16px;opacity:.6">${process.env.APP_NAME} Team</p>
              </div>
              <div class="miro-title-block" style="background-position:center;background-repeat:no-repeat;background-size:100% auto;font-family:Helvetica,Arial,sans-serif;padding:10px 0 12px 40px">
                <div class="miro-title-block__title font-size-42" style="color:#050038;font-family:Helvetica,Arial,sans-serif;font-size:42px!important;font-stretch:normal;font-style:normal;font-weight:700;letter-spacing:normal;line-height:1.24"></div>
              </div>
              <table class="spacer" style="border-collapse:collapse;border-spacing:0;font-family:Helvetica,Arial,sans-serif;padding:0;text-align:left;vertical-align:top;width:100%">
                <tbody style="font-family:Helvetica,Arial,sans-serif">
                  <tr style="font-family:Helvetica,Arial,sans-serif;padding:0;text-align:left;vertical-align:top">
                    <td height="0px" style="-moz-hyphens:auto;-webkit-hyphens:auto;Margin:0;border-collapse:collapse!important;color:#0a0a0a;font-family:Helvetica,Arial,sans-serif;font-size:0;font-weight:400;hyphens:auto;line-height:0;margin:0;mso-line-height-rule:exactly;padding:0;text-align:left;vertical-align:top;word-wrap:break-word"> </td>
                  </tr>
                </tbody>
              </table>
              
              <div class="miro__sep" style="background-color:#e1e0e7;font-family:Helvetica,Arial,sans-serif;height:1px"></div>
            </div>
          </div>
          <div class="miro__footer" style="font-family:Helvetica,Arial,sans-serif;padding-bottom:72px;padding-top:42px"></div>
        </td>
      </tr>
    </table>

    <!-- prevent Gmail on iOS font size manipulation -->
    <div style="display:none;font:15px courier;font-family:Helvetica,Arial,sans-serif;line-height:0;white-space:nowrap">
    </div>
  </body>
  `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log("Verification email sent successfully!");
  } catch (error) {
    console.error("Error sending verification email:", error);
    throw new Error("Error sending verification email!");
  }
};
