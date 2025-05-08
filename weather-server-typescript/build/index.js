import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { validateDeProof, InMemoryNonceStore, } from "./secure-validator.js";
const NWS_API_BASE = "https://api.weather.gov";
const USER_AGENT = "weather-app/1.0";
// Helper function for making NWS API requests
async function makeNWSRequest(url) {
    const headers = {
        "User-Agent": USER_AGENT,
        Accept: "application/geo+json",
    };
    console.log(`[NWS API] Starting request: ${url}`);
    try {
        // Add timeout control
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 15000); // 15-second timeout
        const response = await fetch(url, {
            headers,
            signal: controller.signal,
        });
        clearTimeout(timeoutId); // Clear timeout
        if (!response.ok) {
            console.error(`[NWS API] HTTP error: ${response.status} ${response.statusText}`);
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        console.log(`[NWS API] Successfully received response: ${url}`);
        const data = (await response.json());
        console.log(`[NWS API] Data parsed successfully`);
        return data;
    }
    catch (error) {
        if (error instanceof DOMException && error.name === "AbortError") {
            console.error(`[NWS API] Request timed out: ${url}`);
            return null;
        }
        console.error(`[NWS API] Request failed: ${url}`, error);
        return null;
    }
}
// Format alert data
function formatAlert(feature) {
    const props = feature.properties;
    return [
        `Event: ${props.event || "Unknown"}`,
        `Area: ${props.areaDesc || "Unknown"}`,
        `Severity: ${props.severity || "Unknown"}`,
        `Status: ${props.status || "Unknown"}`,
        `Headline: ${props.headline || "No headline"}`,
        "---",
    ].join("\n");
}
// Create nonce store
const nonceStore = new InMemoryNonceStore();
// Add request timeout control configuration
const TOOL_EXECUTION_TIMEOUT_MS = 20000; // 20-second timeout
const VALIDATION_TIMEOUT_MS = 5000; // 5-second validation timeout
// Higher-order function for DeProof validation
function withDeProofValidation(handler) {
    return async (fullParams, context) => {
        const startTime = Date.now();
        console.log(`\n\n=========== Server received tool call request ===========\n` +
            `Time: ${new Date().toISOString()}\n` +
            `Tool Name: ${context?.toolName || "Unknown tool"}\n` +
            `Request ID: ${context?.raw?.id || "Unknown"}\n` +
            `=============================================\n`);
        // Prepare the request object to be validated
        const requestToValidate = {
            params: fullParams,
            id: context?.raw?.id,
            method: context?.raw?.method,
        };
        // Validate DeProof
        try {
            // Create validation Promise and timeout Promise
            const validationPromise = validateDeProof(requestToValidate, nonceStore);
            const timeoutPromise = new Promise((_resolve, reject) => {
                setTimeout(() => {
                    reject(new Error(`DeProof validation timed out (${VALIDATION_TIMEOUT_MS / 1000} seconds)`));
                }, VALIDATION_TIMEOUT_MS);
            });
            // Race the two Promises
            const validationErrorOrNull = await Promise.race([
                validationPromise,
                timeoutPromise,
            ]).catch((error) => ({
                code: -32099,
                message: error instanceof Error ? error.message : String(error),
            }));
            // If validation returns an error (non-null), then the request fails
            if (validationErrorOrNull !== null) {
                // validationErrorOrNull is now guaranteed to be of type ErrorResponse
                console.error(`DeProof validation failed:`, validationErrorOrNull);
                return {
                    content: [
                        {
                            type: "text",
                            text: `DeProof validation failed: ${validationErrorOrNull.message}`,
                        },
                    ],
                    _meta: {
                        error: validationErrorOrNull,
                    },
                };
            }
            // Extract actual tool parameters from parameters (remove _deProof)
            const actualParams = { ...fullParams };
            delete actualParams._deProof;
            // Now execute the actual tool processing logic
            const validationTime = Date.now() - startTime;
            console.log(`DeProof validation passed! Time taken ${validationTime}ms, starting tool execution...`);
            // Add tool execution timeout protection
            const handlerPromise = handler(actualParams);
            const toolTimeoutPromise = new Promise((_, reject) => {
                setTimeout(() => {
                    reject(new Error(`Tool execution timed out (${TOOL_EXECUTION_TIMEOUT_MS / 1000} seconds)`));
                }, TOOL_EXECUTION_TIMEOUT_MS);
            });
            // Execute tool and return result
            try {
                const result = await Promise.race([handlerPromise, toolTimeoutPromise]);
                const totalTime = Date.now() - startTime;
                console.log(`Tool execution completed! Total time taken ${totalTime}ms`);
                return result;
            }
            catch (error) {
                console.error(`Tool execution error:`, error);
                return {
                    content: [
                        {
                            type: "text",
                            text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`,
                        },
                    ],
                    _meta: {
                        error: {
                            code: -32008,
                            message: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`,
                        },
                    },
                };
            }
        }
        catch (error) {
            console.error(`DeProof validation or tool execution exception:`, error);
            return {
                content: [
                    {
                        type: "text",
                        text: `Request processing exception: ${error instanceof Error ? error.message : String(error)}`,
                    },
                ],
                _meta: {
                    error: {
                        code: -32000,
                        message: `Request processing exception: ${error instanceof Error ? error.message : String(error)}`,
                    },
                },
            };
        }
    };
}
// Create server instance
const server = new McpServer({
    name: "weather",
    version: "1.0.0",
});
// Register weather tools
server.tool("get-alerts", "Get weather alerts for a state", {
    state: z.string().length(2).describe("Two-letter state code (e.g. CA, NY)"),
    _deProof: z
        .object({
        signerAddress: z.string(),
        nonce: z.number(),
        session: z.string(),
        timestamp: z.string(),
        digest: z.string(),
        signature: z.string(),
    })
        .optional()
        .describe("Security validation data"),
}, withDeProofValidation(async ({ state }) => {
    const stateCode = state.toUpperCase();
    const alertsUrl = `${NWS_API_BASE}/alerts?area=${stateCode}`;
    console.log(`Processing get-alerts request: ${state}`);
    const alertsData = await makeNWSRequest(alertsUrl);
    if (!alertsData) {
        return {
            content: [
                {
                    type: "text",
                    text: "Failed to retrieve alerts data",
                },
            ],
        };
    }
    const features = alertsData.features || [];
    if (features.length === 0) {
        return {
            content: [
                {
                    type: "text",
                    text: `No active alerts for ${stateCode}`,
                },
            ],
        };
    }
    const formattedAlerts = features.map(formatAlert);
    const alertsText = `Active alerts for ${stateCode}:\n\n${formattedAlerts.join("\n")}`;
    return {
        content: [
            {
                type: "text",
                text: alertsText,
            },
        ],
    };
}));
server.tool("get-forecast", "Get weather forecast for a location", {
    latitude: z.number().min(-90).max(90).describe("Latitude of the location"),
    longitude: z
        .number()
        .min(-180)
        .max(180)
        .describe("Longitude of the location"),
    _deProof: z
        .object({
        signerAddress: z.string(),
        nonce: z.number(),
        session: z.string(),
        timestamp: z.string(),
        digest: z.string(),
        signature: z.string(),
    })
        .optional()
        .describe("Security validation data"),
}, withDeProofValidation(async ({ latitude, longitude, }) => {
    // Add critical debug log - if you see this log, it means DeProof validation passed and the tool handler function was executed
    console.log(`===== get-forecast tool is executing! Coordinates: (${latitude}, ${longitude}) =====`);
    console.time("get-forecast tool execution time");
    try {
        // Get grid point data
        const pointsUrl = `${NWS_API_BASE}/points/${latitude.toFixed(4)},${longitude.toFixed(4)}`;
        console.log("Requesting NWS API point data:", pointsUrl);
        const pointsData = await makeNWSRequest(pointsUrl);
        if (!pointsData) {
            console.log("Could not get point data");
            return {
                content: [
                    {
                        type: "text",
                        text: `Failed to retrieve grid point data for coordinates: ${latitude}, ${longitude}. This location may not be supported by the NWS API (only US locations are supported).`,
                    },
                ],
            };
        }
        const forecastUrl = pointsData.properties?.forecast;
        if (!forecastUrl) {
            console.log("Could not get forecast URL from point data");
            return {
                content: [
                    {
                        type: "text",
                        text: "Failed to get forecast URL from grid point data",
                    },
                ],
            };
        }
        console.log("Requesting forecast data:", forecastUrl);
        // Get forecast data
        const forecastData = await makeNWSRequest(forecastUrl);
        if (!forecastData) {
            return {
                content: [
                    {
                        type: "text",
                        text: "Failed to retrieve forecast data",
                    },
                ],
            };
        }
        const periods = forecastData.properties?.periods || [];
        if (periods.length === 0) {
            return {
                content: [
                    {
                        type: "text",
                        text: "No forecast periods available",
                    },
                ],
            };
        }
        // Format forecast periods
        const formattedForecast = periods.map((period) => [
            `${period.name || "Unknown"}:`,
            `Temperature: ${period.temperature || "Unknown"}°${period.temperatureUnit || "F"}`,
            `Wind: ${period.windSpeed || "Unknown"} ${period.windDirection || ""}`,
            `${period.shortForecast || "No forecast available"}`,
            "---",
        ].join("\n"));
        const forecastText = `Forecast for ${latitude}, ${longitude}:\n\n${formattedForecast.join("\n")}`;
        return {
            content: [
                {
                    type: "text",
                    text: forecastText,
                },
            ],
        };
    }
    finally {
        console.timeEnd("get-forecast tool execution time");
    }
}));
// Start the server
async function main() {
    try {
        console.log("==============================");
        console.log("Weather MCP Server starting...");
        console.log("Full DeProof validation mechanism integrated");
        console.log("==============================");
        const transport = new StdioServerTransport();
        server.connect(transport);
        console.log("Weather MCP Server running on stdio");
    }
    catch (error) {
        console.error("Failed to start server:", error);
        process.exit(1);
    }
}
main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
