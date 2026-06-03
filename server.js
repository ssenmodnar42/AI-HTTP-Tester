const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const OpenAI = require("openai");

dotenv.config();

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

const client = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});

app.post("/api/ask-ai", async (req, res) => {
    try {
        const { message, requestText, responseText } = req.body;

        const aiResponse = await client.responses.create({
            model: "gpt-5.5",
            input: `
You are helping analyze HTTP requests and responses for a student security testing project.

User message:
${message}

HTTP request:
${requestText}

HTTP response:
${responseText}

Give a short, beginner-friendly explanation.
Do not provide instructions for attacking real websites.
Focus on safe testing, debugging, and learning.
            `
        });

        res.json({
            reply: aiResponse.output_text
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            error: "AI request failed."
        });
    }
});

app.get("/demo/file", (req, res) => {
    const name = (req.query.name || "").toLowerCase();

    const vulnerable =
        name.includes("../") ||
        name.includes("..\\") ||
        name.includes("%2e%2e") ||
        name.includes("passwd") ||
        name.includes("win.ini");

    const review =
        name.includes("....//") ||
        name.includes("config") ||
        name.includes("backup");

    if (vulnerable) {
        return res.status(200).send(`
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
VULNERABILITY_CONFIRMED
        `);
    }

    if (review) {
        return res.status(200).json({
            status: "review",
            message: "Suspicious path, but no sensitive data returned"
        });
    }

    res.status(200).json({
        status: "safe",
        message: "Normal file returned"
    });
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});