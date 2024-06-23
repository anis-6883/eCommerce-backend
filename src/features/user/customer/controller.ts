import bcrypt from "bcrypt";
import { Request, Response } from "express";
import { COOKIE_KEY, REFRESH_TOKEN_KEY, ROLE } from "../../../configs/constants";
import { apiResponse, asyncHandler, exclude, generateSignature, getRandomInteger } from "../../../helpers";
import { IApiRequest, IUser } from "../../../types";
import { sendVerificationEmail } from "../service";
import { customerRegisterSchema, loginSchema, verifyOtpSchema } from "../validation";
import Customer from "./model";

/**
 * Customer Registration & Send Otp
 * @param {Request} req - The HTTP request object.
 * @param {Response} res - The HTTP response object.
 * @returns {Promise<void>} - A promise that resolves when the response is sent.
 */
export const customerRegistration = asyncHandler(async (req: Request, res: Response) => {
  const result = await customerRegisterSchema.validateAsync(req.body);

  const { otp, otpExpiry, isVerified, verifiedAt, image, ref, ...customerBody } = result;

  customerBody.password = await bcrypt.hash(customerBody.password, 10);
  customerBody.otp = getRandomInteger(100000, 999999);
  customerBody.otpExpiry = new Date(Date.now() + 2 * 60 * 1000); // 2 min

  const existingCustomer: IUser = await Customer.findOne({ email: customerBody.email });

  if (existingCustomer && existingCustomer.isVerified) {
    throw "This customer already exists!";
  }

  if (existingCustomer) {
    await Customer.updateOne(
      { email: customerBody.email },
      { otp: customerBody.otp, otpExpiry: customerBody.otpExpiry }
    );
  } else {
    await Customer.create(customerBody);
  }

  const tempToken = generateSignature({ email: customerBody.email, role: ROLE.CUSTOMER }, "15m"); // 15 min

  res.cookie("temp", tempToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "development" ? false : true,
    sameSite: process.env.NODE_ENV === "development" ? "lax" : "none",
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
  });

  sendVerificationEmail(customerBody.email, customerBody.otp);

  return apiResponse(res, 201, true, "Otp send successfully!");
});

/**
 * Customer Otp Verify & Login
 * @param {Request} req - The HTTP request object.
 * @param {Response} res - The HTTP response object.
 * @returns {Promise<void>} - A promise that resolves when the response is sent.
 */
export const customerOtpVerify = asyncHandler(async (req: IApiRequest, res: Response) => {
  const result = await verifyOtpSchema.validateAsync(req.body);

  if (req.user.isVerified) {
    throw "This customer already verified!";
  }

  const isVerified = req.user.otp === Number(result.otp) && req.user.otpExpiry > new Date();
  if (!isVerified) throw "Invalid OTP!";

  await Customer.updateOne(
    { email: req.user.email },
    { isVerified: true, verifiedAt: new Date(), otp: null, otpExpiry: null }
  );

  const customer: any = await Customer.findOneAndUpdate(
    { email: req.user.email },
    { isVerified: true, verifiedAt: new Date(), otp: null, otpExpiry: null },
    {
      new: true,
      projection: { password: 0, otp: 0, otpExpiry: 0 },
    }
  );

  const accessToken = generateSignature({ email: req.user.email, role: ROLE.CUSTOMER }, "1d");
  const refreshToken = generateSignature({ email: req.user.email, role: ROLE.CUSTOMER }, "7d");

  res.cookie(COOKIE_KEY, accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "development" ? false : true,
    sameSite: process.env.NODE_ENV === "development" ? "lax" : "none",
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
  });

  res.cookie(REFRESH_TOKEN_KEY, refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "development" ? false : true,
    sameSite: process.env.NODE_ENV === "development" ? "lax" : "none",
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });

  // Clear Temporary Token
  res.clearCookie("temp", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "development" ? false : true,
    sameSite: process.env.NODE_ENV === "development" ? "lax" : "none",
    expires: new Date(Date.now()),
  });

  const data = {
    ...customer._doc,
    role: ROLE.CUSTOMER,
  };

  return apiResponse(res, 200, true, "Otp verified successfully!", data);
});

/**
 * Customer Resend Otp
 * @param {Request} req - The HTTP request object.
 * @param {Response} res - The HTTP response object.
 * @returns {Promise<void>} - A promise that resolves when the response is sent.
 */
export const customerResendOtp = asyncHandler(async (req: IApiRequest, res: Response) => {
  const otp = getRandomInteger(100000, 999999);
  const otpExpiry = new Date(Date.now() + 2 * 60 * 1000); // 2 min

  if (req.user.isVerified) throw "This customer already verified!";

  if (req.user.otpExpiry > new Date()) {
    throw "Try again, 2 minutes later!";
  }

  await Customer.updateOne({ email: req.user.email }, { $set: { otp, otpExpiry } });

  sendVerificationEmail(req.user.email, otp);

  return apiResponse(res, 200, true, "Otp resend successfully!");
});

/**
 * Customer Login
 * @param {Request} req - The HTTP request object.
 * @param {Response} res - The HTTP response object.
 * @returns {Promise<void>} - A promise that resolves when the response is sent.
 */
export const customerLogin = asyncHandler(async (req: Request, res: Response) => {
  const result = await loginSchema.validateAsync(req.body, {
    abortEarly: false,
  });

  const customer: any = await Customer.findOne({ email: result.email });
  if (!customer) return apiResponse(res, 401, false, "Please, complete your registration first!");

  if (!customer.isVerified) {
    await Customer.deleteOne({ email: result.email });
    return apiResponse(res, 401, false, "Please, complete your registration first!");
  }

  const isPasswordValid = await bcrypt.compare(result.password, customer.password);
  if (!isPasswordValid) return apiResponse(res, 401, false, "Invalid Credentials!");

  const accessToken = generateSignature({ email: customer.email, role: ROLE.CUSTOMER }, "1d");
  const refreshToken = generateSignature({ email: customer.email, role: ROLE.CUSTOMER }, "7d");

  res.cookie(COOKIE_KEY, accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "development" ? false : true,
    sameSite: process.env.NODE_ENV === "development" ? "lax" : "none",
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
  });

  res.cookie(REFRESH_TOKEN_KEY, refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "development" ? false : true,
    sameSite: process.env.NODE_ENV === "development" ? "lax" : "none",
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });

  // Remove Sensitive Data
  const data = exclude(customer._doc, ["password", "otp", "otpExpiry"]);

  return apiResponse(res, 200, true, "Customer Login Successfully!", { ...data, role: ROLE.CUSTOMER });
});

/**
 * Customer Profile
 * @param {Request} req - The HTTP request object.
 * @param {Response} res - The HTTP response object.
 * @returns {Promise<void>} - A promise that resolves when the response is sent.
 */
export const customerProfile = asyncHandler(async (req: IApiRequest, res: Response) => {
  // Remove Sensitive Data
  const data = exclude(req.user, ["password", "otp", "otpExpiry"]);

  return apiResponse(res, 200, true, "Customer Profile", { ...data, role: ROLE.CUSTOMER });
});
