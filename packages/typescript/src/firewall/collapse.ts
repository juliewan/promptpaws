const RUN = /\b(?:\w[\s._\-*`~|]+){2,}\w\b/gu;
const INTRA = /(?<=\w)[._\-*`~|](?=\w)/gu;
const RUN_SEPARATORS = /[\s._\-*`~|]+/gu;

export function collapseWordBreaks(text: string): string {
  return text
    .replace(RUN, (match) => match.replace(RUN_SEPARATORS, ""))
    .replace(INTRA, "");
}
