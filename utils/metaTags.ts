import fs from 'fs';
import path from 'path';

interface MetaTagsData {
  title: string;
  description: string;
  image?: string;
  url: string;
  type: 'website' | 'article' | 'profile';
  author?: string;
}

/**
 * Detect if the request is from a social media bot/crawler
 */
export function isSocialBot(userAgent: string | undefined): boolean {
  if (!userAgent) return false;
  
  const botPatterns = [
    'facebookexternalhit',
    'Facebot',
    'Twitterbot',
    'LinkedInBot',
    'Slackbot',
    'WhatsApp',
    'TelegramBot',
    'DiscordBot',
    'Discordbot',
    'discord',
    'pinterest',
    'Pinterestbot',
    'Slackbot-LinkExpanding',
    'redditbot',
    'Embedly',
    'quora link preview',
    'outbrain',
    'Baiduspider',
    'bingbot',
    'Googlebot',
    'Yahoo! Slurp',
    'msnbot',
    'DuckDuckBot',
  ];
  
  const lowerUserAgent = userAgent.toLowerCase();
  const isBot = botPatterns.some(pattern => lowerUserAgent.includes(pattern.toLowerCase()));
  
  // Log bot detection for debugging
  if (isBot) {
    console.log(`[SSR] Bot detected: ${userAgent}`);
  }
  
  return isBot;
}

/**
 * Strip HTML tags and format text for meta descriptions
 */
export function stripHtmlAndFormat(html: string): string {
  return html
    .replace(/<br\s*\/?>/gi, ' ')
    .replace(/<\/p>/gi, ' ')
    .replace(/<[^>]+>/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Truncate text to a specific length
 */
export function truncateText(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength - 3) + '...';
}

/**
 * Escape HTML special characters
 */
export function escapeHtml(text: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, char => map[char]);
}

/**
 * Generate a minimal HTML document when index.html cannot be found
 */
function generateMinimalHtml(data: MetaTagsData): string {
  const baseUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
  const imageUrl = data.image 
    ? (data.image.startsWith('http') ? data.image : `${baseUrl}${data.image}`)
    : `${baseUrl}/icon512_maskable.png`;

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${escapeHtml(data.title)}</title>
    
    <!-- Open Graph / Facebook -->
    <meta property="og:type" content="${data.type}" />
    <meta property="og:title" content="${escapeHtml(data.title)}" />
    <meta property="og:description" content="${escapeHtml(data.description)}" />
    <meta property="og:url" content="${escapeHtml(data.url)}" />
    <meta property="og:image" content="${imageUrl}" />
    <meta property="og:image:width" content="1200" />
    <meta property="og:image:height" content="630" />
    <meta property="og:site_name" content="Axioris" />
    ${data.author ? `<meta property="article:author" content="${escapeHtml(data.author)}" />` : ''}

    <!-- Twitter -->
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="${escapeHtml(data.title)}" />
    <meta name="twitter:description" content="${escapeHtml(data.description)}" />
    <meta name="twitter:image" content="${imageUrl}" />
    ${data.author ? `<meta name="twitter:creator" content="@${escapeHtml(data.author)}" />` : ''}
    <meta name="twitter:site" content="@axioris" />
  </head>
  <body>
    <div id="root"></div>
  </body>
</html>`;
}

/**
 * Generate HTML with injected meta tags for social media crawlers
 */
export function generateHtmlWithMetaTags(data: MetaTagsData): string {
  // Try to find index.html in either root or dist folder
  let htmlPath = path.join(process.cwd(), 'index.html');
  
  if (!fs.existsSync(htmlPath)) {
    // Try dist folder for production builds
    htmlPath = path.join(process.cwd(), 'dist', 'index.html');
  }
  
  if (!fs.existsSync(htmlPath)) {
    // Fallback to public folder
    htmlPath = path.join(process.cwd(), 'public', 'index.html');
  }
  
  let html: string;
  try {
    html = fs.readFileSync(htmlPath, 'utf-8');
  } catch (error) {
    console.error('Failed to read index.html from any location:', error);
    // Return a minimal HTML with meta tags
    return generateMinimalHtml(data);
  }
  
  const escapedTitle = escapeHtml(data.title);
  const escapedDescription = escapeHtml(data.description);
  const escapedUrl = escapeHtml(data.url);
  
  // Build the full URL for the image
  const baseUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
  const imageUrl = data.image 
    ? (data.image.startsWith('http') ? data.image : `${baseUrl}${data.image}`)
    : `${baseUrl}/icon512_maskable.png`;
  
  // Update the document title
  html = html.replace(/<title>.*?<\/title>/, `<title>${escapedTitle}</title>`);
  
  // Remove existing OG and Twitter meta tags
  html = html.replace(/<meta\s+property="og:[^"]+"\s+content="[^"]*"\s*\/>/g, '');
  html = html.replace(/<meta\s+name="twitter:[^"]+"\s+content="[^"]*"\s*\/>/g, '');
  
  // Build new meta tags
  const metaTags = `
    <!-- Open Graph / Facebook -->
    <meta property="og:type" content="${data.type}" />
    <meta property="og:title" content="${escapedTitle}" />
    <meta property="og:description" content="${escapedDescription}" />
    <meta property="og:url" content="${escapedUrl}" />
    <meta property="og:image" content="${imageUrl}" />
    <meta property="og:image:width" content="1200" />
    <meta property="og:image:height" content="630" />
    <meta property="og:site_name" content="Axioris" />
    ${data.author ? `<meta property="article:author" content="${escapeHtml(data.author)}" />` : ''}

    <!-- Twitter -->
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="${escapedTitle}" />
    <meta name="twitter:description" content="${escapedDescription}" />
    <meta name="twitter:image" content="${imageUrl}" />
    ${data.author ? `<meta name="twitter:creator" content="@${escapeHtml(data.author)}" />` : ''}
    <meta name="twitter:site" content="@axioris" />`;
  
  // Insert the new meta tags in the <head> section
  html = html.replace('</head>', `${metaTags}\n  </head>`);
  
  return html;
}
