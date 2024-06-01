import express from "express";
import { refreshAccessToken, tokenVerify } from "../features/user/controller";
import retailerAuthRoutes from "../features/user/retailer/route";

const router = express.Router();

router.use("/token-verify", tokenVerify);
router.use("/refresh-token", refreshAccessToken);
router.use("/user", retailerAuthRoutes);

export default router;
