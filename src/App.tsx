import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Button,
  Field,
  FluentProvider,
  Input,
  Link,
  MessageBar,
  MessageBarBody,
  MessageBarTitle,
  ProgressBar,
  webDarkTheme,
} from "@fluentui/react-components";
import { shorthands, tokens } from "@fluentui/react-components";
import { Event, listen } from "@tauri-apps/api/event";
import "reset-css";
import { Message, ValidationState, MessageKind } from "./interfaces";
import { Col, SectionTitle, Row } from "./helper-components";
import { css, keyframes } from "@emotion/react";
import {    } from "@tauri-apps/api";
import * as dialog from "@tauri-apps/plugin-dialog"
import * as process from "@tauri-apps/plugin-process"
import * as shell from "@tauri-apps/plugin-shell"

const getProgress = (message?: Message): number => {
  switch (message?.kind) {
    case MessageKind.Progress:
      return message.value;
    case MessageKind.Completed:
      return 1;
    default:
      return 0;
  }
};

const octocatWave = keyframes`
0%,
to {
  transform:rotate(0)
}
20%,
60% {
  transform:rotate(-25deg)
}
40%,
80% {
  transform:rotate(10deg)
}
`;

const App = () => {
  const [inputFile, setInputFile] = useState("");
  const [outputDir, setOutputDir] = useState("");
  const [message, setMessage] = useState<Message | undefined>(undefined);

  useEffect(() => {
    const unlisten = listen("reporter", (e: Event<Message>) => {
      console.log(e.payload);
      setMessage(e.payload);
    });
    return () => {
      unlisten.then((f) => f());
    };
  }, []);

  return (
    <FluentProvider
      css={{
        boxSizing: 'border-box',
        height: '100vh',
        ...shorthands.padding(
          tokens.spacingVerticalXXXL,
          tokens.spacingHorizontalXXXL
        ),
      }}
      theme={webDarkTheme}
    >
      {/* <>
        <a
          href="https://github.com/colinhacks/zod"
          target="_blank"
          class="github-corner"
          aria-label="View source on Github"
        >
          <svg viewBox="0 0 250 250" aria-hidden="true">
            <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
            <path
              d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2"
              fill="currentColor"
              style="transform-origin: 130px 106px;"
              class="octo-arm"
            ></path>
            <path
              d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z"
              fill="currentColor"
              class="octo-body"
            ></path>
          </svg>
        </a>
      </> */}
      <Link
        href="#"
        css={css`
          border-bottom: 0;
          position: fixed;
          right: 0;
          text-decoration: none;
          top: 0;
          z-index: 1;
        `}
        onClick={async () =>
          await shell.open("https://github.com/crazystylus/otadump")
        }
      >
        <svg
          viewBox="0 0 250 250"
          aria-hidden="true"
          css={css`
            color: #fff;
            fill: var(--theme-color, #42b983);
            height: 80px;
            width: 80px;
          `}
        >
          <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
          <path
            d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2"
            fill="currentColor"
            css={css`
              transform-origin: 130px 106px;
              -webkit-animation: ${octocatWave} 0.56s ease-in-out;
              animation: ${octocatWave} 0.56s ease-in-out;
              &:hover {
                -webkit-animation: none;
                animation: none;
              }
            `}
          ></path>
          <path
            d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z"
            fill="currentColor"
          ></path>
        </svg>
      </Link>
      <div
        css={css`
          display: flex;
          flex-direction: column;
          gap: 24px;
          height: 100%;
          // box-sizing: border-box;
          // min-height: 100vh;
          // /* mobile viewport bug fix */
          // min-height: -webkit-fill-available;
        `}
      >
        <div css={{ height: 'fit-content', overflow: "auto", flexShrink:0 }}>
          <Col
            css_={{
              alignItems: "flex-start",
              flexShrink: 1,
              width: "100%",
              gap: "4px",
            }}
          >
            <SectionTitle label="Extraction" />
            <Field label="Payload file" css={{ width: "100%", gap: "8px" }}>
              <Row css_={{ gap: "16px" }}>
                <Input
                  css={{ flexGrow: 1 }}
                  disabled={message?.kind === MessageKind.Progress}
                  onChange={(e) => setInputFile(e.currentTarget.value)}
                  value={inputFile}
                />
                <Button
                  appearance="outline"
                  disabled={message?.kind === MessageKind.Progress}
                  onClick={async () => {
                    const inputFile = await dialog.open();
                    if (inputFile === null) {
                      return;
                    }
                    if (Array.isArray(inputFile)) {
                      throw new Error("expected a single file");
                    }
                    setInputFile(inputFile);
                  }}
                >
                  Select
                </Button>
              </Row>
            </Field>
            <Field label="Output directory" css={{ width: "100%", gap: "8px" }}>
              <Row css_={{ gap: "16px" }}>
                <Input
                  css={{ flexGrow: 1 }}
                  disabled={message?.kind === MessageKind.Progress}
                  onChange={(e) => setOutputDir(e.currentTarget.value)}
                  value={outputDir}
                />
                <Button
                  appearance="outline"
                  disabled={message?.kind === MessageKind.Progress}
                  onClick={async () => {
                    const outputDir = await dialog.open({
                      directory: true,
                    });
                    if (outputDir === null) {
                      return;
                    }
                    if (Array.isArray(outputDir)) {
                      throw new Error("expected a single directory");
                    }
                    setOutputDir(outputDir);
                  }}
                >
                  Select
                </Button>
              </Row>
            </Field>
          </Col>

          <Col
            css_={{
              alignItems: "flex-start",
              flexShrink: 1,
              width: "100%",
              gap: "4px",
            }}
          >
            <SectionTitle label="Status" />
            <Col
              css_={{
                alignItems: "flex-start",
                flexGrow: 1,
                width: "100%",
                gap: "16px",
              }}
            >
              <Field
                validationMessage={`${(getProgress(message) * 100).toFixed(
                  1
                )}%`}
                validationMessageIcon={null}
                validationState={
                  ValidationState[message?.kind ?? MessageKind.Progress]
                }
                css={{ width: "100%", gap: "8px" }}
              >
                <ProgressBar
                  css={{ height: "48px" }}
                  thickness="large"
                  value={getProgress(message)}
                />
              </Field>

              {message?.kind === MessageKind.Completed && (
                <MessageBar
                  intent="success"
                  layout="multiline"
                  css={{ width: "100%" }}
                >
                  <MessageBarBody>
                    <MessageBarTitle>Completed</MessageBarTitle>
                    <p>
                      Files were extracted successfully.{" "}
                      <Link
                        href="#"
                        onClick={async () => await shell.open(outputDir)}
                      >
                        Open
                      </Link>
                    </p>
                  </MessageBarBody>
                </MessageBar>
              )}

              {message?.kind === MessageKind.Error && (
                <MessageBar
                  intent="error"
                  layout="multiline"
                  css={{ width: "100%" }}
                >
                  <MessageBarBody>
                    <MessageBarTitle>Error</MessageBarTitle>
                    <pre>{message.message}</pre>
                  </MessageBarBody>
                </MessageBar>
              )}

              <Row css_={{ alignSelf: "flex-end", gap: "16px" }}>
                {message?.kind === MessageKind.Progress ? (
                  <Button onClick={() => console.log("todo")}>Cancel</Button>
                ) : (
                  <Button onClick={async () => await process.exit(0)}>
                    Exit
                  </Button>
                )}

                <Button
                  appearance="primary"
                  disabled={
                    inputFile.trim().length === 0 ||
                    outputDir.trim().length === 0 ||
                    message?.kind === MessageKind.Progress
                  }
                  onClick={() => {
                    invoke("extract", {
                      payloadFile: inputFile,
                      outputDir: outputDir,
                    });
                  }}
                >
                  Extract
                </Button>
              </Row>
            </Col>
          </Col>
        </div>

        <Row
          css_={{
            alignItems: "flex-end",
            height: "100%",
            flexGrow: 1,
            justifyContent: "center",
          }}
        >
          <p css={{ textAlign: "center" }}>
            {"Made with "}
            <span style={{ color: "#d13438" }}>❤</span>
            {" by "}
            <Link
              href="#"
              onClick={async () =>
                await shell.open("https://github.com/crazystylus")
              }
            >
              crazystylus
            </Link>
            {" and "}
            <Link
              href="#"
              onClick={async () =>
                await shell.open("https://github.com/ajeetdsouza")
              }
            >
              ajeetdsouza
            </Link>
            {"."}
          </p>
        </Row>
      </div>
    </FluentProvider>
  );
};

export default App;
