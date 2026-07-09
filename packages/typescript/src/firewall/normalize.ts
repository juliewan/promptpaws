const INVISIBLE = /[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/gu;
const CONTROL = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/gu;

const CONFUSABLES: Readonly<Record<string, string>> = {
  а: "a",
  е: "e",
  о: "o",
  р: "p",
  с: "c",
  у: "y",
  х: "x",
  ο: "o",
  α: "a",
};

export function normalize(text: string): string {
  const cleaned = text.normalize("NFKC").replace(INVISIBLE, "").replace(CONTROL, "");
  return [...cleaned].map((character) => CONFUSABLES[character] ?? character).join("");
}
