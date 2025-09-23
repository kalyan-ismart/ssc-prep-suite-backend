// routes/health.js
const express = require("express");
const mongoose = require("mongoose");
const os = require("os");
const router = express.Router();

router.get("/health", async (req, res) => {
  const start = process.hrtime(); // Start timer

  try {
    // Check MongoDB connection
    const dbConnected = mongoose.connection.readyState === 1; // 1 = connected

    // Calculate response time
    const diff = process.hrtime(start);
    const responseTime = (diff[0] * 1e3 + diff[1] / 1e6).toFixed(2) + "ms";

    // CPU and system info
    const cpuLoad = os.loadavg(); // [1min, 5min, 15min] load average
    const cpuCount = os.cpus().length;

    const healthInfo = {
      version: "2.2",
      environment: process.env.NODE_ENV || "development",
      timestamp: new Date(),
      uptime: `${process.uptime().toFixed(2)}s`,
      memoryUsage: process.memoryUsage(),
      cpu: {
        cores: cpuCount,
        loadAvg: cpuLoad, // normalized load average
      },
      dbConnected,
      responseTime,
    };

    if (!dbConnected) {
      return res.status(500).json({
        success: false,
        message: "Database not connected",
        ...healthInfo,
      });
    }

    res.status(200).json({
      success: true,
      message: "SarkariSuccess-Hub API is running!",
      ...healthInfo,
    });
  } catch (err) {
    const diff = process.hrtime(start);
    const responseTime = (diff[0] * 1e3 + diff[1] / 1e6).toFixed(2) + "ms";

    res.status(500).json({
      success: false,
      message: "Health check failed",
      error: err.message,
      responseTime,
    });
  }
});

module.exports = router;
