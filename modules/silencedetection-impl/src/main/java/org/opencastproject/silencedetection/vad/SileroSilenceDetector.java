/*
 * Licensed to The Apereo Foundation under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 *
 * The Apereo Foundation licenses this file to you under the Educational
 * Community License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package org.opencastproject.silencedetection.vad;

import org.opencastproject.job.api.Job;
import org.opencastproject.mediapackage.Track;
import org.opencastproject.silencedetection.api.MediaSegment;
import org.opencastproject.silencedetection.api.MediaSegments;
import org.opencastproject.silencedetection.api.SilenceDetectionFailedException;
import org.opencastproject.silencedetection.vad.wav.WavFile;
import org.opencastproject.silencedetection.vad.wav.WavFileException;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.workspace.api.Workspace;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

public class SileroSilenceDetector {

  private static final Logger logger = LoggerFactory.getLogger(SileroSilenceDetector.class);

  public static final String FFMPEG_BINARY_CONFIG = "org.opencastproject.composer.ffmpeg.path";
  public static final String FFMPEG_BINARY_DEFAULT = "ffmpeg";

  private static final String COLLECTION = "silencedetection";

  private static String binary = FFMPEG_BINARY_DEFAULT;
  private String filePath;
  private String trackId;

  private List<MediaSegment> segments = null;

  /**
   * Update FFMPEG binary path if set in configuration.
   *
   * @param bundleContext
   */
  public static void init(BundleContext bundleContext) {
    String binaryPath = bundleContext.getProperty(FFMPEG_BINARY_CONFIG);
    try {
      if (StringUtils.isNotBlank(binaryPath)) {
        File binaryFile = new File(StringUtils.trim(binaryPath));
        if (binaryFile.exists()) {
          binary = binaryFile.getAbsolutePath();
        } else {
          logger.warn("FFmpeg binary file {} does not exist", StringUtils.trim(binaryPath));
        }
      }
    } catch (Exception ex) {
      logger.error("Failed to set ffmpeg binary path", ex);
    }
  }


  public SileroSilenceDetector(Properties properties, Track track, Workspace workspace, Job job)
          throws SilenceDetectionFailedException, IOException, InterruptedException, WavFileException {
    try {
      File mediaFile = workspace.get(track.getURI());
      filePath = mediaFile.getAbsolutePath();
    } catch (NotFoundException e) {
      throw new SilenceDetectionFailedException("Error finding the media file in workspace", e);
    } catch (IOException e) {
      throw new SilenceDetectionFailedException("Error reading media file in workspace", e);
    }
    var name = String.format("job-%d", job.getId());
    var jobDir  = Path.of(workspace.rootDirectory(), "collection", COLLECTION, name).toFile();
    var whisperInput = FilenameUtils.concat(jobDir.getAbsolutePath(), UUID.randomUUID() + ".pcm");
    var ffmpegCommand = List.of(
        binary,
        "-i", filePath,
        "-c:a", "pcm_s16le",
        "-f", "s16le",
        "-ar", "16000",
        "-ac", "1",
        whisperInput);

    ProcessBuilder pbuilder = new ProcessBuilder(ffmpegCommand);
    Process process = pbuilder.start();
    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
      String line = reader.readLine();
      while (null != line) {
        logger.debug("FFmpeg output: {}", line);
      }
    } catch (IOException e) {
      logger.error("Error executing ffmpeg", e);
    }

    int exitCode = process.waitFor();
    if (exitCode != 0) {
      throw new SilenceDetectionFailedException("FFmpeg process failed with exit code " + exitCode);
    }

    var silero = new SileroVadSilenceDetection(
        SampleRate.SAMPLE_RATE_16000,
        FrameSize.FRAME_SIZE_1024,
        Mode.NORMAL,
        600, 250, false);

    WavFile wavFile = WavFile.openWavFile(new File(whisperInput));
    List<Boolean> isSpeech = new ArrayList<>();
    for (int i = 0; i < wavFile.getNumFrames() / 1024; i++) {
      short[] audioData = new short[1024];
      wavFile.readFrames(audioData, 1024);
      isSpeech.add(silero.isSpeech(audioData));
    }

    LinkedList<MediaSegment> segmentsTmp = new LinkedList<>();
    if (!isSpeech.isEmpty()) {
      boolean triggered = false;
      int sample = 0;
      double start = 0;

      for (boolean s : isSpeech) {
        sample += 1024;
        if (!triggered && s) {
          triggered = true;
          start = ((double) sample / (double) 16000) - (600 / (double) 1000);
        }
        if (triggered && !s) {
          triggered = false;
          double end = (double) sample / (double) 16000 - (250 / (double) 1000);
          segmentsTmp.add(new MediaSegment((long) start, (long) end));
        }
      }
      if (triggered) {
        double end = (double) sample / (double) 16000 - (250 / (double) 1000);
        segmentsTmp.add(new MediaSegment((long) start, (long) end));
      }
    }

    logger.info("Segmentation of track {} yielded {} segments", trackId, segmentsTmp.size());
    segments = segmentsTmp;

  }

  public MediaSegments getMediaSegments() {
    if (segments == null) {
      return null;
    }

    return new MediaSegments(trackId, filePath, segments);
  }

}
