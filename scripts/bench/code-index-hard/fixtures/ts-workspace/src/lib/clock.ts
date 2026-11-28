export const now = () => new Date().toISOString();
export const inSeconds = (seconds: number) => Math.floor(Date.now() / 1000) + seconds;
