const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");

const app = express();


// ============================================================
// CONFIG
// ============================================================

const PORT = 5000;
const MONGO_URI = "mongodb://127.0.0.1:27017/ai_hids";
const OFFLINE_TIMEOUT = 15 * 1000;


// ============================================================
// MIDDLEWARE
// ============================================================

app.use(cors());
app.use(express.json());
app.set("view engine", "ejs");


/// DATABASE

mongoose
    .connect(MONGO_URI)
    .then(() => console.log("MongoDB Connected"))
    .catch(error => console.error("MongoDB Error:", error.message));


///HOST MODEL

const hostSchema = new mongoose.Schema(
    {
        hostId: { type: String, required: true, unique: true },
        hostname: { type: String, default: "Unknown" },
        os: { type: String, default: "Unknown" },

        cpu: { type: Number, default: 0 },
        ram: { type: Number, default: 0 },
        disk: { type: Number, default: 0 },

        processCount: { type: Number, default: 0 },

        lastSeen: { type: Date, default: Date.now },

        status: {
            type: String,
            enum: ["ONLINE", "OFFLINE"],
            default: "OFFLINE"
        }
    },
    { timestamps: true }
);

const Host = mongoose.model("Host", hostSchema);

///PROCESS MODEL

const processSchema = new mongoose.Schema({
    hostId: { type: String, required: true },
    pid: { type: Number, required: true },

    processName: { type: String, default: "Unknown" },
    executablePath: { type: String, default: "" },
    user: { type: String, default: "" },

    createTime: { type: Number, default: null },

    status: {
        type: String,
        enum: ["RUNNING", "TERMINATED"],
        default: "RUNNING"
    },

    firstSeen: { type: Date, default: Date.now },
    lastSeen: { type: Date, default: Date.now },

    terminatedAt: { type: Date, default: null }
});

processSchema.index(
    { hostId: 1, pid: 1 },
    { unique: true }
);

const Process = mongoose.model("Process", processSchema);


/////FILR EVENT MODELL

const fileEventSchema = new mongoose.Schema(
    {
        hostId: { type: String, required: true },

        eventType: { type: String, required: true },

        fileName: { type: String, default: "" },
        filePath: { type: String, default: "" },
        oldPath: { type: String, default: null },

        timestamp: { type: Date, default: Date.now }
    },
    { timestamps: true }
);

fileEventSchema.index({
    hostId: 1,
    timestamp: -1
});

const FileEvent = mongoose.model(
    "FileEvent",
    fileEventSchema
);


// security event model

const securityEventSchema = new mongoose.Schema(
    {
        hostId: { type: String, required: true },

        eventType: { type: String, required: true },
        eventId: { type: Number, required: true },

        username: { type: String, default: "-" },
        domain: { type: String, default: "-" },
        logonType: { type: String, default: "-" },

        ipAddress: { type: String, default: "-" },
        workstationName: { type: String, default: "-" },

        authenticationPackageName: {
            type: String,
            default: "-"
        },

        recordId: {
            type: Number,
            required: true
        },

        timestamp: {
            type: Date,
            default: Date.now
        }
    },
    { timestamps: true }
);


// Prevent duplicate Windows Security events
securityEventSchema.index(
    { hostId: 1, recordId: 1 },
    { unique: true }
);


// Speed up dashboard queries
securityEventSchema.index({
    hostId: 1,
    timestamp: -1
});

const SecurityEvent = mongoose.model(
    "SecurityEvent",
    securityEventSchema
);


///HELPERS

function getHostStatus(lastSeen) {

    if (!lastSeen) {
        return "OFFLINE";
    }

    const age = Date.now() - new Date(lastSeen).getTime();

    return age > OFFLINE_TIMEOUT
        ? "OFFLINE"
        : "ONLINE";
}


////AGENT TELEME

app.post("/api/agent/data", async (req, res) => {

    try {

        const data = req.body;

        if (!data.hostId) {
            return res.status(400).json({
                success: false,
                message: "hostId is required"
            });
        }


        ///HOST

        await Host.findOneAndUpdate(
            { hostId: data.hostId },

            {
                $set: {
                    hostname: data.hostname || "Unknown",
                    os: data.os || "Unknown",

                    cpu: Number(data.cpu) || 0,
                    ram: Number(data.ram) || 0,
                    disk: Number(data.disk) || 0,

                    processCount:
                        Number(data.processCount) ||
                        (Array.isArray(data.processes)
                            ? data.processes.length
                            : 0),

                    lastSeen: new Date(),
                    status: "ONLINE"
                },

                $setOnInsert: {
                    hostId: data.hostId
                }
            },

            {
                upsert: true,
                new: true
            }
        );


        ///PROCESSE

        if (Array.isArray(data.processes)) {

            const currentPids = data.processes
                .map(process => Number(process.pid))
                .filter(pid => !isNaN(pid));


            for (const process of data.processes) {

                if (!process.pid) {
                    continue;
                }

                const pid = Number(process.pid);


                await Process.findOneAndUpdate(
                    {
                        hostId: data.hostId,
                        pid
                    },

                    {
                        $set: {
                            processName:
                                process.name || "Unknown",

                            executablePath:
                                process.executablePath || "",

                            user:
                                process.user || "",

                            createTime:
                                process.createTime || null,

                            status: "RUNNING",
                            lastSeen: new Date(),
                            terminatedAt: null
                        },

                        $setOnInsert: {
                            hostId: data.hostId,
                            pid,
                            firstSeen: new Date()
                        }
                    },

                    {
                        upsert: true
                    }
                );
            }


            // Mark missing processes as terminated
            await Process.updateMany(
                {
                    hostId: data.hostId,
                    status: "RUNNING",
                    pid: { $nin: currentPids }
                },

                {
                    $set: {
                        status: "TERMINATED",
                        terminatedAt: new Date()
                    }
                }
            );
        }


        console.log(
            `[HIDS] Telemetry: ${data.hostId}`
        );


        res.json({
            success: true,
            message: "Data processed successfully"
        });

    } catch (error) {

        console.error("Agent Data Error:", error);

        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});


/////////FILE EVENS
app.post("/api/agent/file-event", async (req, res) => {

    try {

        const { hostId, event } = req.body;

        if (!hostId) {
            return res.status(400).json({
                success: false,
                message: "hostId is required"
            });
        }

        if (!event) {
            return res.status(400).json({
                success: false,
                message: "event is required"
            });
        }


        await FileEvent.create({
            hostId,

            eventType:
                event.eventType || "UNKNOWN",

            fileName:
                event.fileName || "",

            filePath:
                event.filePath || "",

            oldPath:
                event.oldPath || null,

            timestamp: new Date()
        });


        console.log(
            `[HIDS] File Event: ${event.eventType} - ${event.filePath}`
        );


        res.json({
            success: true,
            message: "File event stored successfully"
        });

    } catch (error) {

        console.error("File Event Error:", error);

        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});


// ============================================================
// WINDOWS SECURITY EVENTS
// ============================================================

app.post("/api/agent/security-event", async (req, res) => {

    try {

        const { hostId, event } = req.body;

        if (!hostId) {
            return res.status(400).json({
                success: false,
                message: "hostId is required"
            });
        }

        if (!event) {
            return res.status(400).json({
                success: false,
                message: "event is required"
            });
        }

        if (!event.recordId) {
            return res.status(400).json({
                success: false,
                message: "recordId is required"
            });
        }


        const recordId = Number(event.recordId);


        await SecurityEvent.findOneAndUpdate(

            {
                hostId,
                recordId
            },

            {
                $set: {
                    eventType:
                        event.eventType || "UNKNOWN",

                    eventId:
                        Number(event.eventId) || 0,

                    username:
                        event.username || "-",

                    domain:
                        event.domain || "-",

                    logonType:
                        event.logonType || "-",

                    ipAddress:
                        event.ipAddress || "-",

                    workstationName:
                        event.workstationName || "-",

                    authenticationPackageName:
                        event.authenticationPackageName || "-",

                    timestamp:
                        event.timestamp
                            ? new Date(event.timestamp)
                            : new Date()
                },

                $setOnInsert: {
                    hostId,
                    recordId
                }
            },

            {
                upsert: true,
                new: true
            }
        );


        console.log(
            `[HIDS] Security Event: ${event.eventType} | ID: ${event.eventId} | User: ${event.username}`
        );


        res.json({
            success: true,
            message: "Security event stored successfully"
        });

    } catch (error) {

        console.error("Security Event Error:", error);

        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});


/////////DASHBOARD

app.get("/hids", async (req, res) => {

    try {

        const hostId = "PC-001";

        const host = await Host.findOne({ hostId });

        const processes = await Process
            .find({ hostId })
            .sort({ status: 1, processName: 1 });


        if (host) {
            host.status = getHostStatus(host.lastSeen);
        }


        res.render("hids", {
            host,
            processes
        });

    } catch (error) {

        console.error(
            "Dashboard Render Error:",
            error
        );

        res.status(500).send(
            "Unable to load HIDS dashboard"
        );
    }
});


//////HOST API

app.get("/api/host/:hostId", async (req, res) => {

    try {

        const host = await Host.findOne({
            hostId: req.params.hostId
        });


        if (!host) {
            return res.status(404).json({
                success: false,
                message: "Host not found"
            });
        }


        const status = getHostStatus(host.lastSeen);


        if (host.status !== status) {
            host.status = status;
            await host.save();
        }


        res.json({
            success: true,

            host: {
                hostId: host.hostId,
                hostname: host.hostname,
                os: host.os,

                cpu: host.cpu,
                ram: host.ram,
                disk: host.disk,

                processCount: host.processCount,

                lastSeen: host.lastSeen,
                status
            }
        });

    } catch (error) {

        console.error("Host API Error:", error);

        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});


///////PROCESS API

app.get("/api/processes/:hostId", async (req, res) => {

    try {

        const processes = await Process
            .find({
                hostId: req.params.hostId
            })
            .sort({
                status: 1,
                processName: 1
            });


        res.json({
            success: true,
            count: processes.length,
            processes
        });

    } catch (error) {

        console.error("Process API Error:", error);

        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});


///////////SECURITY EVENTS API

app.get("/api/security-events/:hostId", async (req, res) => {

    try {

        const events = await SecurityEvent
            .find({
                hostId: req.params.hostId
            })
            .sort({
                timestamp: -1
            })
            .limit(50);


        res.json({
            success: true,
            count: events.length,
            events
        });

    } catch (error) {

        console.error(
            "Security Events API Error:",
            error
        );

        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

////////////FILE EVENTS API

app.get("/api/file-events/:hostId", async (req, res) => {
    try {
        const events = await FileEvent
            .find({ hostId: req.params.hostId })
            .sort({ timestamp: -1 })
            .limit(50);

        res.json({
            success: true,
            count: events.length,
            events
        });

    } catch (error) {
        console.error("File Events API Error:", error);

        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});
///////////////ROOT

app.get("/", (req, res) => {

    res.send(`
        <h1>AI-HIDS Server</h1>
        <p>Server is running.</p>
        <a href="/hids">Open HIDS Dashboard</a>
    `);

});


////////////////////STATRT

app.listen(PORT, () => {

    console.log("------------------------------------");
    console.log(`AI-HIDS Server running on Port ${PORT}`);
    console.log(`Offline Timeout: ${OFFLINE_TIMEOUT / 1000}s`);
    console.log("------------------------------------");

});