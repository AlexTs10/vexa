/**
 * Where the join layer writes its checkpoint screenshots.
 *
 * `VEXA_SCREENSHOT_DIR` names the folder; the bot image's folder is the default. A host run (the
 * native Mac app's process backend) has no `/app`, so its bot launcher gives each bot a folder of
 * its own.
 */
export const SCREENSHOT_DIR: string = process.env.VEXA_SCREENSHOT_DIR || '/app/storage/screenshots';

/** The path of one checkpoint screenshot in {@link SCREENSHOT_DIR}. */
export function screenshotPath(name: string): string {
  return `${SCREENSHOT_DIR}/${name}`;
}
