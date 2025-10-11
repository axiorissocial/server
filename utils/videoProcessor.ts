import ffmpegInstaller from '@ffmpeg-installer/ffmpeg';
import ffprobeInstaller from '@ffprobe-installer/ffprobe';
import { spawn } from 'child_process';
import fs from 'fs-extra';
import path from 'path';

export interface VideoProcessingResult {
  hlsPath: string;
  thumbnailPath: string;
  duration: number;
  resolution: {
    width: number;
    height: number;
  };
}

type VideoQuality = {
  name: string;
  resolution: string;
  videoBitrate: string;
  audioBitrate: string;
  bufferSize: string;
};

type FfprobeStream = {
  codec_type?: string;
  width?: number;
  height?: number;
};

type FfprobeMetadata = {
  format?: {
    duration?: string;
  };
  streams?: FfprobeStream[];
};

const FFMPEG_PATH = ffmpegInstaller.path;
const FFPROBE_PATH = ffprobeInstaller.path;

export class VideoProcessor {
  private static readonly HLS_SEGMENT_DURATION = 10;
  private static readonly THUMBNAIL_TIME = '00:00:01';

  static async processToHLS(
    inputPath: string,
    outputDir: string,
    filename: string
  ): Promise<VideoProcessingResult> {
    await fs.ensureDir(outputDir);

    const baseOutputPath = path.join(outputDir, filename);
    const hlsOutputPath = `${baseOutputPath}.m3u8`;
    const thumbnailPath = `${baseOutputPath}_thumb.jpg`;

    const metadata = await this.getVideoMetadata(inputPath);

    await this.generateThumbnail(inputPath, thumbnailPath);
    await this.convertToHLS(inputPath, hlsOutputPath, metadata.resolution);

    return {
      hlsPath: hlsOutputPath,
      thumbnailPath,
      duration: metadata.duration,
      resolution: metadata.resolution
    };
  }

  static async convertHLSToMP4(
    hlsPath: string,
    outputPath: string
  ): Promise<void> {
    await fs.ensureDir(path.dirname(outputPath));

    await this.runCommand(FFMPEG_PATH, [
      '-y',
      '-i',
      hlsPath,
      '-c',
      'copy',
      '-bsf:a',
      'aac_adtstoasc',
      outputPath
    ]);
  }

  static async transcodeToMP4(
    inputPath: string,
    outputPath: string
  ): Promise<void> {
    await fs.ensureDir(path.dirname(outputPath));

    await this.runCommand(FFMPEG_PATH, [
      '-y',
      '-i',
      inputPath,
      '-c:v',
      'libx264',
      '-preset',
      'fast',
      '-profile:v',
      'main',
      '-c:a',
      'aac',
      '-b:a',
      '128k',
      '-movflags',
      '+faststart',
      outputPath
    ]);
  }

  private static async getVideoMetadata(inputPath: string): Promise<{
    duration: number;
    resolution: { width: number; height: number };
  }> {
    const output = await this.runCommandWithOutput(FFPROBE_PATH, [
      '-v',
      'quiet',
      '-print_format',
      'json',
      '-show_format',
      '-show_streams',
      inputPath
    ]);

  const metadata = JSON.parse(output) as FfprobeMetadata;
  const videoStream = (metadata.streams || []).find((stream) => stream.codec_type === 'video');

    if (!videoStream) {
      throw new Error('No video stream found when probing file');
    }

    return {
      duration: Number(metadata.format?.duration) || 0,
      resolution: {
        width: Number(videoStream.width) || 0,
        height: Number(videoStream.height) || 0
      }
    };
  }

  private static async generateThumbnail(
    inputPath: string,
    outputPath: string
  ): Promise<void> {
    await fs.ensureDir(path.dirname(outputPath));

    await this.runCommand(FFMPEG_PATH, [
      '-y',
      '-ss',
      this.THUMBNAIL_TIME,
      '-i',
      inputPath,
      '-frames:v',
      '1',
      outputPath
    ]);
  }

  private static async convertToHLS(
    inputPath: string,
    outputPath: string,
    resolution: { width: number; height: number }
  ): Promise<void> {
    const qualities = this.determineQualityLevels(resolution.width, resolution.height);

    for (const quality of qualities) {
      const segmentPath = outputPath.replace('.m3u8', `_${quality.name}_%03d.ts`);
      const playlistPath = outputPath.replace('.m3u8', `_${quality.name}.m3u8`);

      await this.runCommand(FFMPEG_PATH, [
        '-y',
        '-i',
        inputPath,
        '-map',
        '0:v:0',
        '-map',
        '0:a:0?',
        '-c:v',
        'libx264',
        '-preset',
        'fast',
        '-profile:v',
        'main',
        '-b:v',
        quality.videoBitrate,
        '-maxrate',
        quality.videoBitrate,
        '-bufsize',
        quality.bufferSize,
        '-vf',
        `scale=${quality.resolution}`,
        '-c:a',
        'aac',
        '-b:a',
        quality.audioBitrate,
        '-ac',
        '2',
        '-f',
        'hls',
        '-hls_time',
        this.HLS_SEGMENT_DURATION.toString(),
        '-hls_list_size',
        '0',
        '-hls_playlist_type',
        'vod',
        '-hls_flags',
        'independent_segments',
        '-hls_segment_filename',
        segmentPath,
        playlistPath
      ]);
    }

    await this.createMasterPlaylist(outputPath, qualities);
  }

  private static determineQualityLevels(width: number, height: number): VideoQuality[] {
    const qualities: VideoQuality[] = [];

    if (height >= 1080) {
      qualities.push({
        name: '1080p',
        resolution: '1920x1080',
        videoBitrate: '5000k',
        audioBitrate: '128k',
        bufferSize: '10000k'
      });
    }

    if (height >= 720) {
      qualities.push({
        name: '720p',
        resolution: '1280x720',
        videoBitrate: '2500k',
        audioBitrate: '128k',
        bufferSize: '5000k'
      });
    }

    if (height >= 480) {
      qualities.push({
        name: '480p',
        resolution: '854x480',
        videoBitrate: '1000k',
        audioBitrate: '96k',
        bufferSize: '2000k'
      });
    }

    qualities.push({
      name: '360p',
      resolution: '640x360',
      videoBitrate: '500k',
      audioBitrate: '96k',
      bufferSize: '1000k'
    });

    return qualities;
  }

  private static async createMasterPlaylist(
    masterPath: string,
    qualities: VideoQuality[]
  ): Promise<void> {
    let masterContent = '#EXTM3U\n#EXT-X-VERSION:3\n\n';

    for (const quality of qualities) {
      const bandwidth = parseInt(quality.videoBitrate.replace('k', ''), 10) * 1000;
      const playlistName = path.basename(masterPath).replace('.m3u8', `_${quality.name}.m3u8`);

      masterContent += `#EXT-X-STREAM-INF:BANDWIDTH=${bandwidth},RESOLUTION=${quality.resolution}\n`;
      masterContent += `${playlistName}\n`;
    }

    await fs.writeFile(masterPath, masterContent);
  }

  static async cleanupVideoFiles(mediaDir: string): Promise<void> {
    try {
      const ROOT_MEDIA_DIR = path.resolve(process.cwd(), 'public', 'uploads', 'media');
      const resolvedMediaDir = path.resolve(mediaDir);
      if (!resolvedMediaDir.startsWith(ROOT_MEDIA_DIR + path.sep)) {
        console.error('Refusing to clean up files for mediaDir outside allowed directory:', resolvedMediaDir);
        return;
      }

      const exists = await fs.pathExists(resolvedMediaDir);
      if (!exists) return;

      const files = await fs.readdir(resolvedMediaDir);
      const removableExtensions = ['.m3u8', '.ts'];

      await Promise.all(
        files
          .filter(file => removableExtensions.includes(path.extname(file).toLowerCase()))
          .map(file => fs.remove(path.join(resolvedMediaDir, file)).catch(() => undefined))
      );
    } catch (error) {
      console.error('Error cleaning up video files:', error);
    }
  }

  private static runCommand(binary: string, args: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const child = spawn(binary, args, {
        windowsHide: true
      });

      let stderr = '';

      child.stderr?.on('data', (data) => {
        stderr += data.toString();
      });

      child.on('error', (error) => reject(error));
      child.on('close', (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Command failed (${code}): ${binary} ${args.join(' ')}\n${stderr}`));
        }
      });
    });
  }

  private static runCommandWithOutput(binary: string, args: string[]): Promise<string> {
    return new Promise((resolve, reject) => {
      const child = spawn(binary, args, {
        windowsHide: true
      });

      let stdout = '';
      let stderr = '';

      child.stdout?.on('data', (data) => {
        stdout += data.toString();
      });

      child.stderr?.on('data', (data) => {
        stderr += data.toString();
      });

      child.on('error', (error) => reject(error));
      child.on('close', (code) => {
        if (code === 0) {
          resolve(stdout);
        } else {
          reject(new Error(`Command failed (${code}): ${binary} ${args.join(' ')}\n${stderr}`));
        }
      });
    });
  }
}