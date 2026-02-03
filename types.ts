export enum AppMode {
  CHAT = 'CHAT',
  IMAGINE = 'IMAGINE',
  VISION = 'VISION'
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'model';
  content: string;
  timestamp: number;
}

export interface GeneratedImage {
  id: string;
  url: string;
  prompt: string;
  timestamp: number;
}

export interface VisionAnalysis {
  id: string;
  imageUrl: string;
  prompt: string;
  result: string;
  timestamp: number;
}
