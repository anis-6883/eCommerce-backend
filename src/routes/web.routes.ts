import express from "express";
import { getUserProfile, refreshAccessToken, userLogout, verifyToken } from "../features/user/controller";
import customerAuthRoutes from "../features/user/customer/route";
import { authAndPermissionCheck } from "../middlewares/authMiddleware";

const router = express.Router();

// Common Routes
router.get("/verify-token", authAndPermissionCheck("", false, false), verifyToken);
router.get("/refresh-token", authAndPermissionCheck("", false), refreshAccessToken);
router.get("/user-profile", authAndPermissionCheck("", false), getUserProfile);
router.post("/user-logout", authAndPermissionCheck("", false), userLogout);

router.use("/customer/auth", customerAuthRoutes);

export default router;
