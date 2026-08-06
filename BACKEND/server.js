const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

app.post("/api/agent/data", (req, res) => {

    console.log("Received Data");

    console.log(req.body);

    res.json({
        success: true
    });

});

app.listen(5000, () => {

    console.log("Server Running on Port 5000");

});