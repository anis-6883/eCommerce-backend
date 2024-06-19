import { NextFunction, Response } from "express";
import jwt from "jsonwebtoken";
import { Model } from "mongoose";
import { COOKIE_KEY, ROLE } from "../configs/constants";
import Admin from "../features/user/admin/model";
import Customer from "../features/user/customer/model";
import { apiResponse } from "../helpers";
import { IApiRequest } from "../types";

export const authAndPermissionCheck =
  (role: string, checkPermission: boolean = true, findUser: boolean = true) =>
  async (req: IApiRequest, res: Response, next: NextFunction): Promise<any> => {
    try {
      const token =
        req?.cookies?.temp || req.headers?.authorization?.replace("Bearer ", "") || req?.cookies?.[COOKIE_KEY];
      if (!token) return apiResponse(res, 401, false, "Unauthorized Request!");

      const decoded: any = jwt.verify(token, process.env.APP_SECRET!);
      let model: Model<any>;

      if (checkPermission && role !== decoded.role) {
        return apiResponse(res, 403, false, "You are not authorized to perform this action!");
      }

      if (findUser) {
        switch (decoded.role) {
          case ROLE.ADMIN:
            model = Admin;
            break;
          case ROLE.CUSTOMER:
            model = Customer;
            break;
          default:
            return apiResponse(res, 401, false, "Unauthorized!");
        }

        const user: any = await model.findOne({ email: decoded?.email });
        if (!user) return apiResponse(res, 401, false, "Unauthorized Request!");
        req.user = user._doc;
      }

      req.token = token;
      req.role = decoded.role;
      return next();
    } catch (err) {
      console.error(err);
      return apiResponse(res, 401, false, "Unauthorized Request!");
    }
  };
