export interface ChannelTarget {
  kind: string;
  id: string;
}

export function parseChannel(channel: string): ChannelTarget | null {
  const index = channel.indexOf(":");
  if (index <= 0 || index === channel.length - 1) return null;
  return { kind: channel.slice(0, index), id: channel.slice(index + 1) };
}
