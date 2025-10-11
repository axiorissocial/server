import { Router, Request, Response, NextFunction } from 'express';
import { prisma } from '../index.js';
import { isSocialBot, generateHtmlWithMetaTags, stripHtmlAndFormat, truncateText } from '../utils/metaTags.js';

const router = Router();

/**
 * SSR route for profile pages - serves HTML with proper meta tags for social media crawlers
 * Handles /profile/:username (with or without @ prefix)
 */
router.get('/profile/:username', async (req: Request, res: Response, next: NextFunction) => {
  const userAgent = req.get('User-Agent');
  
  console.log(`[SSR] Profile request: ${req.params.username}, User-Agent: ${userAgent}`);
  
  // If not a social bot, pass to next handler (React app in dev, or static files in production)
  if (!isSocialBot(userAgent)) {
    console.log(`[SSR] Not a bot, passing to next handler`);
    return next();
  }

  console.log(`[SSR] Bot detected, generating SSR HTML for profile: ${req.params.username}`);

  try {
    let { username } = req.params;
    
    // Strip @ prefix if present
    username = username.replace(/^@/, '');

    // Find user by username (case-insensitive)
    const user = await prisma.user.findFirst({
      where: {
        username: {
          equals: username,
        },
        isPrivate: false,
      },
      include: {
        profile: {
          select: {
            displayName: true,
            avatar: true,
            avatarGradient: true,
            bio: true,
          }
        }
      }
    });

    if (!user) {
      // User not found - pass to next handler
      return next();
    }

    // Determine display name
    const displayName = user.profile?.displayName || user.username;
    const title = `${displayName} (@${user.username})`;

    // Get bio
    const bio = user.profile?.bio || user.bio || `Check out ${displayName}'s profile on Axioris`;
    const description = truncateText(bio, 300);

    // Get profile picture - if gradient avatar, use logo instead
    let profileImage: string | undefined;
    if (user.profile?.avatar && !user.profile.avatarGradient) {
      profileImage = user.profile.avatar;
    }
    // If avatarGradient is set or no avatar, we'll use the default logo (undefined = fallback to logo)

    // Build the full URL
    const baseUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    const fullUrl = `${baseUrl}/profile/@${user.username}`;

    // Generate HTML with meta tags
    const html = generateHtmlWithMetaTags({
      title: `${title} - Axioris`,
      description: description,
      image: profileImage,
      url: fullUrl,
      type: 'profile',
      author: user.username,
    });

    console.log(`[SSR] Successfully generated HTML for profile: ${user.username}`);
    res.setHeader('Content-Type', 'text/html');
    res.send(html);

  } catch (error) {
    console.error('Error generating profile meta tags:', error);
    next();
  }
});

/**
 * SSR route for post pages - serves HTML with proper meta tags for social media crawlers
 * Handles both /post/:id and /post/:slug routes
 */
router.get('/post/:idOrSlug', async (req: Request, res: Response, next: NextFunction) => {
  const userAgent = req.get('User-Agent');
  
  console.log(`[SSR] Post request: ${req.params.idOrSlug}, User-Agent: ${userAgent}`);
  
  // If not a social bot, pass to next handler (React app in dev, or static files in production)
  if (!isSocialBot(userAgent)) {
    console.log(`[SSR] Not a bot, passing to next handler`);
    return next();
  }

  console.log(`[SSR] Bot detected, generating SSR HTML for post: ${req.params.idOrSlug}`);

  try {
    const { idOrSlug } = req.params;
    
    // Try to find post by ID first, then by slug
    const post = await prisma.post.findFirst({
      where: {
        OR: [
          { id: idOrSlug },
          { slug: idOrSlug }
        ],
        isPrivate: false,
      },
      include: {
        user: {
          select: {
            username: true,
            profile: {
              select: {
                displayName: true,
              }
            }
          }
        }
      }
    });

    if (!post) {
      // Post not found - pass to next handler
      return next();
    }

    // Get the first media item (prefer images over videos)
    let firstMedia: string | undefined;
    if (post.media && Array.isArray(post.media)) {
      const media = post.media as Array<{ url: string; type: string }>;
      const imageMedia = media.find(m => m.type === 'image');
      const anyMedia = media[0];
      
      if (imageMedia) {
        firstMedia = imageMedia.url;
      } else if (anyMedia && anyMedia.type === 'image') {
        firstMedia = anyMedia.url;
      }
    }

    // Strip HTML and prepare content for description
    const contentText = stripHtmlAndFormat(post.content);
    const description = truncateText(contentText, 300);

    // Prepare title
    const title = post.title || 'Post';
    const fullTitle = `${title} - Axioris`;

    // Get author name
    const authorName = post.user.profile?.displayName || post.user.username;

    // Build the full URL
    const baseUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    const fullUrl = `${baseUrl}/post/${post.slug || post.id}`;

    // Generate HTML with meta tags
    const html = generateHtmlWithMetaTags({
      title: fullTitle,
      description: description,
      image: firstMedia,
      url: fullUrl,
      type: 'article',
      author: authorName,
    });

    console.log(`[SSR] Successfully generated HTML for post: ${post.id}`);
    res.setHeader('Content-Type', 'text/html');
    res.send(html);

  } catch (error) {
    console.error('Error generating post meta tags:', error);
    next();
  }
});

export default router;
