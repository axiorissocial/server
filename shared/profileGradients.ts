export interface ProfileGradient {
  id: string;
  label: string;
  stops: string[];
  angle?: number;
  textColor?: string;
}

export const profileGradients: ProfileGradient[] = [
  {
    id: 'aurora-sky',
    label: 'Aurora Sky',
    stops: ['#7F7FD5', '#86A8E7', '#91EAE4']
  },
  {
    id: 'sunset-haze',
    label: 'Sunset Haze',
    stops: ['#ff7e5f', '#feb47b']
  },
  {
    id: 'forest-canopy',
    label: 'Forest Canopy',
    stops: ['#76b852', '#8DC26F']
  },
  {
    id: 'ocean-breeze',
    label: 'Ocean Breeze',
    stops: ['#00c6ff', '#0072ff']
  },
  {
    id: 'violet-dream',
    label: 'Violet Dream',
    stops: ['#4776E6', '#8E54E9']
  },
  {
    id: 'sunrise-glow',
    label: 'Sunrise Glow',
    stops: ['#f6d365', '#fda085']
  },
  {
    id: 'neon-noir',
    label: 'Neon Noir',
    stops: ['#0f2027', '#203a43', '#2c5364'],
    textColor: '#F3F4F6'
  },
  {
    id: 'ember-heat',
    label: 'Ember Heat',
    stops: ['#f12711', '#f5af19']
  },
  {
    id: 'berry-splash',
    label: 'Berry Splash',
    stops: ['#ff758c', '#ff7eb3']
  },
  {
    id: 'lunar-mist',
    label: 'Lunar Mist',
    stops: ['#bdc3c7', '#2c3e50'],
    textColor: '#111827'
  }
];

export const defaultGradientAngle = 135;

export const profileGradientMap = new Map(profileGradients.map((gradient) => [gradient.id, gradient] as const));

export const profileGradientIds = profileGradients.map((gradient) => gradient.id);

export const getProfileGradientCss = (
  id: string,
  fallback: string = 'linear-gradient(135deg, #4C1D95, #2563EB)'
): string => {
  const gradient = profileGradientMap.get(id);
  if (!gradient) {
    return fallback;
  }

  const angle = gradient.angle ?? defaultGradientAngle;
  return `linear-gradient(${angle}deg, ${gradient.stops.join(', ')})`;
};

export const getProfileGradientTextColor = (id: string, fallback = '#FFFFFF'): string => {
  return profileGradientMap.get(id)?.textColor ?? fallback;
};

export const getRandomGradientId = (): string => {
  const index = Math.floor(Math.random() * profileGradientIds.length);
  return profileGradientIds[index];
};
