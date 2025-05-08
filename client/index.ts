import OpenAI from "openai";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import readline from "readline/promises";
import dotenv from "dotenv";
import type {
  ChatCompletionMessageParam,
  ChatCompletionTool,
} from "openai/resources/index.mjs";
import { Wallet } from "ethers";
import { generateDeProof, DeProof } from "./secure-proof.js";

dotenv.config();

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
if (!OPENAI_API_KEY) {
  throw new Error("OPENAI_API_KEY is not set");
}

// Private key for signing, should be securely stored in production
const PRIVATE_KEY = process.env.WALLET_PRIVATE_KEY;
if (!PRIVATE_KEY) {
  throw new Error("WALLET_PRIVATE_KEY is not set");
}

// Add type definition for tool call results
interface ToolCallResult {
  content: string | any;
  [key: string]: any;
}

// Add request timeout constants
const TOOL_CALL_TIMEOUT_MS = 3000; // 3 seconds
const MCP_CONNECTION_TIMEOUT_MS = 1000; // 1 second

class MCPClient {
  private mcp: Client;
  private openai: OpenAI;
  private tools: ChatCompletionTool[] = [];
  private wallet: Wallet;
  private session: string | null = null;

  constructor() {
    this.openai = new OpenAI({
      apiKey: OPENAI_API_KEY,
      baseURL: process.env.OPENAI_BASE_URL,
    });
    this.mcp = new Client({ name: "mcp-client-cli", version: "1.0.0" });
    // Initialize wallet for signing
    this.wallet = new Wallet(PRIVATE_KEY as string);
  }

  async connectToServer(serverScriptPath: string) {
    /**
     * Connect to an MCP server
     *
     * @param serverScriptPath - Path to the server script (.py or .js)
     */
    try {
      console.log(`\n========= Connecting to MCP server =========`);
      console.log(`Server script path: ${serverScriptPath}`);

      // Determine script type and appropriate command
      const isJs = serverScriptPath.endsWith(".js");
      const isPy = serverScriptPath.endsWith(".py");
      if (!isJs && !isPy) {
        throw new Error("Server script must be a .js or .py file");
      }
      const command = isPy
        ? process.platform === "win32"
          ? "python"
          : "python3"
        : process.execPath;

      console.log(`Using command: ${command} ${serverScriptPath}`);

      // Create transport
      const transport = new StdioClientTransport({
        command,
        args: [serverScriptPath],
      });

      console.log(`Attempting to connect to server...`);

      // Add connection timeout control
      try {
        const connectPromise = this.mcp.connect(transport);
        const timeoutPromise = new Promise((_, reject) => {
          setTimeout(() => {
            reject(
              new Error(
                `Connection to MCP server timeout (${
                  MCP_CONNECTION_TIMEOUT_MS / 1000
                } seconds)`
              )
            );
          }, MCP_CONNECTION_TIMEOUT_MS);
        });

        await Promise.race([connectPromise, timeoutPromise]);
        console.log(`Successfully connected to MCP server`);
      } catch (error) {
        console.error(`Failed to connect to MCP server:`, error);
        throw error;
      }

      // List available tools and convert to LLM format
      console.log(`Getting server tool list...`);
      const toolsResult = await this.mcp.listTools();
      this.tools = toolsResult.tools.map((tool) => {
        return {
          type: "function",
          function: {
            name: tool.name as string,
            description: tool.description as string,
            parameters: tool.inputSchema as Record<string, any>,
          },
        };
      });
      console.log(
        "Available tools:",
        this.tools.map((tool) => tool.function.name)
      );
    } catch (e) {
      console.log("Failed to connect to MCP server: ", e);
      throw e;
    }
  }

  async processQuery(query: string) {
    /**
     * Process a query using LLM and available tools
     *
     * @param query - The user's input query
     * @returns Processed response as a string
     */
    const messages: ChatCompletionMessageParam[] = [
      {
        role: "user",
        content: query,
      },
    ];

    try {
      console.log("\n==========================================");
      console.log("Sending request to LLM...");
      console.log("==========================================");

      // Create LLM request object and send directly
      const openaiRequestParams = {
        model: process.env.OPENAI_MODEL as string,
        messages: messages,
        tools: this.tools.length > 0 ? this.tools : undefined,
        tool_choice: this.tools.length > 0 ? ("auto" as const) : undefined,
      };

      const response = await this.openai.chat.completions.create(
        openaiRequestParams
      );

      console.log("Received LLM response");

      if (
        !response.choices ||
        response.choices.length === 0 ||
        !response.choices[0].message
      ) {
        console.error("LLM response missing required fields", response);
        return "Error: LLM returned an invalid response";
      }
      const responseMessage = response.choices[0].message;
      const toolCalls = responseMessage.tool_calls;

      // Process response and handle tool calls
      let finalResponseText = "";

      if (toolCalls) {
        console.log(
          "LLM requests tool call:",
          toolCalls.map((tc) => tc.function.name)
        );
        messages.push(responseMessage);

        // Process tool calls serially - no longer using Promise.all for parallel calls
        try {
          // Process each tool call sequentially
          for (const toolCall of toolCalls) {
            const toolName = toolCall.function.name;
            const rawToolArgs = JSON.parse(toolCall.function.arguments);

            console.log(`\n=========================================`);
            console.log(`Calling tool: ${toolName}`);
            console.log(`Raw Parameters from LLM:`, rawToolArgs);
            console.log(`=========================================`);

            // Create a "clean" version of arguments for DeProof generation
            // by removing any _deProof that LLM might have included.
            const deProofGenArgs = { ...rawToolArgs };
            if ("_deProof" in deProofGenArgs) {
              delete deProofGenArgs["_deProof"];
            }

            console.log(
              `Generating DeProof validation data for (cleaned) parameters:`,
              deProofGenArgs
            );
            const deProof: DeProof = await generateDeProof(
              deProofGenArgs, // Use cleaned args for DeProof generation
              this.wallet,
              this.session
            );

            // If it's a new session, update the client session state
            if (!this.session) {
              this.session = deProof.session;
              console.log(
                `Created new session: ${this.session.substring(0, 8)}...`
              );
            }

            // Add validation data to parameters, using the cleaned args as base
            const secureArgs = {
              ...deProofGenArgs, // Start with cleaned args
              _deProof: deProof, // Add the real _deProof
            };

            // Add tool call timeout control
            const callToolWithTimeout = async () => {
              // Create Promise for the tool call - using parameters with security data
              const toolCallPromise = this.mcp.callTool({
                name: toolName,
                arguments: secureArgs,
              });

              // Create timeout Promise
              const timeoutPromise = new Promise((_resolve, reject) => {
                setTimeout(() => {
                  reject(
                    new Error(
                      `Tool call ${toolName} timed out after ${
                        TOOL_CALL_TIMEOUT_MS / 1000
                      } seconds`
                    )
                  );
                }, TOOL_CALL_TIMEOUT_MS);
              });

              try {
                // Race the two Promises, return whoever finishes first
                return await Promise.race([toolCallPromise, timeoutPromise]);
              } catch (error) {
                console.error(`Failed to call tool ${toolName}:`, error);
                throw error;
              }
            };

            try {
              console.log(
                `Starting tool call: ${toolName}, using full DeProof validation`
              );
              const result = (await callToolWithTimeout()) as ToolCallResult;
              console.log(
                `Tool ${toolName} returned result:`,
                JSON.stringify(result.content).substring(0, 200) + "..."
              );

              messages.push({
                tool_call_id: toolCall.id,
                role: "tool",
                content: result.content as string,
              });
            } catch (error) {
              console.error(`Error calling tool ${toolName}:`, error);
              const errorMsg =
                error instanceof Error
                  ? `Tool call error: ${error.message}`
                  : `Tool call error: ${String(error)}`;

              console.log(`Sending error information back to LLM:`, errorMsg);

              messages.push({
                tool_call_id: toolCall.id,
                role: "tool",
                content: errorMsg,
              });
            }
          }

          console.log(
            "All tool calls completed, sending results back to LLM..."
          );
        } catch (error) {
          console.error("Error executing one or more tool calls:", error);
          return `Error executing tool calls: ${
            error instanceof Error ? error.message : String(error)
          }`;
        }

        // The second LLM request
        console.log("\n==========================================");
        console.log("Sending tool results back to LLM to get final reply...");
        console.log("==========================================");

        const secondResponse = await this.openai.chat.completions.create({
          model: process.env.OPENAI_MODEL as string,
          messages: messages,
        });

        console.log("Received final LLM response");
        if (
          !secondResponse.choices ||
          secondResponse.choices.length === 0 ||
          !secondResponse.choices[0].message
        ) {
          console.error(
            "LLM second response missing required fields",
            secondResponse
          );
          return "Error: LLM returned an invalid response after processing tool call results";
        }
        finalResponseText = secondResponse.choices[0].message.content || "";
      } else {
        finalResponseText = responseMessage.content || "";
      }

      return finalResponseText;
    } catch (error) {
      console.error("Error processing query with LLM:", error);
      if (error instanceof OpenAI.APIError) {
        return `LLM error: ${error.status} ${error.name} ${error.message}`;
      }
      return `Unexpected error occurred: ${
        error instanceof Error ? error.message : String(error)
      }`;
    }
  }

  async chatLoop() {
    /**
     * Run an interactive chat loop
     */
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    try {
      console.log("\n=================================");
      console.log("MCP client started (using full DeProof validation)");
      console.log("Enter your question or type 'quit' to exit");
      console.log("=================================");

      while (true) {
        const message = await rl.question("\nQuestion: ");
        if (message.toLowerCase() === "quit") {
          break;
        }
        if (!message.trim()) {
          continue;
        }
        console.log("\nProcessing...");
        const response = await this.processQuery(message);
        console.log("\nAnswer:\n" + response);
      }
    } finally {
      rl.close();
    }
  }

  async cleanup() {
    /**
     * Clean up resources
     */
    console.log("\nCleaning up resources...");
    try {
      await this.mcp.close();
      console.log("Successfully closed MCP connection");
    } catch (error) {
      console.error("Error closing MCP connection:", error);
    }
  }
}

async function main() {
  if (process.argv.length < 3) {
    console.log("Usage: node build/index.js <server script path>");
    console.log("Ensure 'npm run build' is run first!");
    return;
  }
  const mcpClient = new MCPClient();
  try {
    await mcpClient.connectToServer(process.argv[2]);
    await mcpClient.chatLoop();
  } catch (error) {
    console.error("\nError occurred during execution:", error);
  } finally {
    await mcpClient.cleanup();
    process.exit(0);
  }
}

main();
