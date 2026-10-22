import { ConvexError } from "convex/values";

/** Rust komutlarından, Convex'ten ve tarayıcıdan gelen hataları kullanıcıya
 * gösterilebilir metne çevirir. */
export function errorMessage(error: unknown): string {
  if (error instanceof ConvexError) {
    return typeof error.data === "string" ? error.data : JSON.stringify(error.data);
  }

  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}
