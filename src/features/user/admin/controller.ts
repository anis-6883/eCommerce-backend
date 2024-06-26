import bcrypt from "bcrypt";
import { Request, Response } from "express";
import { IApiRequest } from "types";
import { COOKIE_KEY, REFRESH_TOKEN_KEY, ROLE } from "../../../configs/constants";
import { apiResponse, asyncHandler, exclude, generateSignature } from "../../../helpers";
import { adminRegisterSchema, loginSchema } from "../validation";
import Admin from "./model";

/**
 *  Admin Registration
 * @param {Request} req - The HTTP request object.
 * @param {Response} res - The HTTP response object.
 * @returns {Promise<void>} - A promise that resolves when the response is sent.
 */
export const adminRegistration = asyncHandler(async (req: Request, res: Response) => {
  const result = await adminRegisterSchema.validateAsync(req.body);

  const existingAdmin = await Admin.findOne({ email: result.email });
  if (existingAdmin) return apiResponse(res, 400, false, "This Admin already exists!");

  result.password = await bcrypt.hash(result.password, 10);

  const admin: any = await Admin.create(result);

  const data = exclude(admin._doc, ["password", "createdAt", "updatedAt"]);

  return apiResponse(res, 201, true, "Admin registration successfully!", data);
});

/**
 *  Admin Login
 * @param {Request} req - The HTTP request object.
 * @param {Response} res - The HTTP response object.
 * @returns {Promise<void>} - A promise that resolves when the response is sent.
 */
export const adminLogin = asyncHandler(async (req: Request, res: Response) => {
  const result = await loginSchema.validateAsync(req.body);

  const admin: any = await Admin.findOne({ email: result.email });
  if (!admin) return apiResponse(res, 401, false, "Invalid Credentials!");

  const isPasswordValid = await bcrypt.compare(result.password, admin.password);
  if (!isPasswordValid) return apiResponse(res, 401, false, "Invalid Credentials!");

  const accessToken = generateSignature({ email: admin.email, role: ROLE.ADMIN }, "1d");
  const refreshToken = generateSignature({ email: admin.email, role: ROLE.ADMIN }, "7d");

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

  const data = exclude(admin._doc, ["password", "createdAt", "updatedAt"]);

  return apiResponse(res, 200, true, "Admin Login Successfully!", { ...data, role: ROLE.ADMIN });
});

/**
 *  Admin Logout
 * @param {Request} req - The HTTP request object.
 * @param {Response} res - The HTTP response object.
 * @returns {Promise<void>} - A promise that resolves when the response is sent.
 */
export const adminLogout = asyncHandler(async (_req: Request, res: Response) => {
  res.clearCookie(COOKIE_KEY, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "development" ? false : true,
    sameSite: process.env.NODE_ENV === "development" ? "lax" : "none",
    expires: new Date(Date.now()),
  });

  res.clearCookie(REFRESH_TOKEN_KEY, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "development" ? false : true,
    sameSite: process.env.NODE_ENV === "development" ? "lax" : "none",
    expires: new Date(Date.now()),
  });

  return apiResponse(res, 200, true, "Admin Logout Successfully!");
});

/**
 *  Admin Profile
 * @param {Request} req - The HTTP request object.
 * @param {Response} res - The HTTP response object.
 * @returns {Promise<void>} - A promise that resolves when the response is sent.
 */
export const adminProfile = asyncHandler(async (req: IApiRequest, res: Response) => {
  const data = exclude(req.user, ["password", "createdAt", "updatedAt"]);

  return apiResponse(res, 200, true, "Admin Profile", { ...data, role: req.role });
});
