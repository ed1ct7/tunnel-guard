export type Page = "overview" | "routing" | "processes" | "connection";

export const pageTitles: Record<Page, string> = {
  overview: "Обзор",
  routing: "Маршрутизация",
  processes: "Процессы",
  connection: "Подключение",
};
