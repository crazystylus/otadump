import { CSSObject } from "@emotion/react";

export type Message = Progress | Error | Completed;

export enum MessageKind {
  Progress = "Progress",
  Error = "Error",
  Completed = "Completed",
}

export interface Progress {
  kind: MessageKind.Progress;
  value: number;
}

export interface Error {
  kind: MessageKind.Error;
  message: string;
}

export interface Completed {
  kind: MessageKind.Completed;
}

export const ValidationState: Record<
  MessageKind,
  "error" | "warning" | "success" | "none"
> = {
  [MessageKind.Error]: "error",
  [MessageKind.Progress]: "none",
  [MessageKind.Completed]: "success",
};

export interface FlexProps {
  children: React.ReactNode;
  css_?: CSSObject;
}
