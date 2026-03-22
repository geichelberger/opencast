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

import static java.util.function.Predicate.not;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.nio.LongBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OnnxTensorLike;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;

public class SileroVadSilenceDetection implements AutoCloseable {

  private SampleRate sampleRate;
  private FrameSize frameSize;
  private Mode mode;
  private int speechDurationMs;
  private int silenceDurationMs;

  private int speechFramesCount = 0;
  private int silenceFramesCount = 0;
  private int maxSpeechFramesCount;
  private int maxSilenceFramesCount;

  private boolean isInitiated = false;

  private OrtSession session;

  private float[] h = new float[128];
  private float[] c = new float[128];

  private boolean useCuda = false;

  public SileroVadSilenceDetection(SampleRate sampleRate, FrameSize frameSize, Mode mode) {
    this(sampleRate, frameSize, mode, 0,0, false);
  }

  public SileroVadSilenceDetection(SampleRate sampleRate, FrameSize frameSize, Mode mode, int speechDurationMs,
      int silenceDurationMs, boolean useCuda) {
    this.sampleRate = sampleRate;
    this.frameSize = frameSize;
    this.mode = mode;
    setSilenceDurationMs(silenceDurationMs);
    setSpeechDurationMs(speechDurationMs);

    var env = OrtEnvironment.getEnvironment();

    try (var sessionOptions = new OrtSession.SessionOptions()) {
      sessionOptions.setInterOpNumThreads(1);
      sessionOptions.setIntraOpNumThreads(1);
      sessionOptions.setOptimizationLevel(OrtSession.SessionOptions.OptLevel.ALL_OPT);
      if (useCuda) {
        sessionOptions.addCUDA();
      } else {
        sessionOptions.addCPU(true);
      }

      var model = Objects.requireNonNull(
          Thread.currentThread()
              .getContextClassLoader()
              .getResourceAsStream("model/silero_vad.onnx")
      ).readAllBytes();
      session = env.createSession(model, sessionOptions);
      isInitiated = true;
    } catch (IOException | OrtException e) {
      throw new RuntimeException(e);
    }

  }

  private enum InputTensors {
    INPUT("input"),
    SR("sr"),
    H("h"),
    C("c");

    private final String name;

    InputTensors(String name) {
      this.name = name;
    }

    public String getTensorName() {
      return name;
    }
  }

  private enum OutputTensors {
    OUTPUT(0),
    HN(1),
    CN(2);

    private final int name;

    OutputTensors(int name) {
      this.name = name;
    }

    public int getTensorName() {
      return name;
    }
  }


  private void checkState() {
    if (!isInitiated) {
      throw new IllegalStateException("VadSilero is not initiated");
    }
  }

  private float[][] unpack(OrtSession.Result output, int index) {
    float[][] result = null;
    try {
      result = (float[][]) output.get(index).getValue();
    } catch (OrtException e) {
      throw new RuntimeException(e);
    }
    return result;
  }
  private float[][][] unpack3D(OrtSession.Result output, int index) {
    float[][][] result = null;
    try {
      result = (float[][][]) output.get(index).getValue();
    } catch (OrtException e) {
      throw new RuntimeException(e);
    }
    return result;
  }

  private float getResult(OrtSession.Result output) {
    float[][] confidence = unpack(output, OutputTensors.OUTPUT.getTensorName());

    c = flatten3DArray(unpack3D(output, OutputTensors.CN.getTensorName()));
    h = flatten3DArray(unpack3D(output, OutputTensors.HN.getTensorName()));

    if (confidence != null && confidence.length > 0 && confidence[0].length > 0) {
      return confidence[0][0];
    } else {
      return 0f;
    }
  }

  private float[] flattenArray(float[][] array) {
    if (array == null || array.length == 0) {
      return null;
    }

    int length = 0;
    for (float[] inner : array) {
      length += inner.length;
    }

    float[] flattened = new float[length];
    int index = 0;
    for (float[] inner : array) {
      for (float value : inner) {
        flattened[index++] = value;
      }
    }
    return flattened;
  }

  public static float[] flatten3DArray(float[][][] array3D) {
    int totalSize = 0;
    for (float[][] array2D : array3D) {
      for (float[] array1D : array2D) {
        totalSize += array1D.length;
      }
    }

    float[] flattenedArray = new float[totalSize];
    int index = 0;

    for (float[][] array2D : array3D) {
      for (float[] array1D : array2D) {
        for (float value : array1D) {
          flattenedArray[index++] = value;
        }
      }
    }

    return flattenedArray;
  }

  public Map<String, OnnxTensor> getInputTensors(float[] audioData) {

    // Validate input audio block is long enough
    if (((float) sampleRate.value()) / audioData.length > 31.25) {
      throw new IllegalArgumentException("Input audio is too short");
    }

    OrtEnvironment env = OrtEnvironment.getEnvironment();

    try {
      Map<String, OnnxTensor> inputTensors = new HashMap<>();
      inputTensors.put(InputTensors.INPUT.getTensorName(),
          OnnxTensor.createTensor(env, FloatBuffer.wrap(audioData), new long[] { 1, frameSize.value() }));
      inputTensors.put(InputTensors.SR.getTensorName(),
          OnnxTensor.createTensor(env, LongBuffer.wrap(new long[] { sampleRate.value() }), new long[] { 1 }));
      inputTensors.put(InputTensors.H.getTensorName(),
          OnnxTensor.createTensor(env, FloatBuffer.wrap(h), new long[] { 2, 1, 64 }));
      inputTensors.put(InputTensors.C.getTensorName(),
          OnnxTensor.createTensor(env, FloatBuffer.wrap(c), new long[] { 2, 1, 64 }));
      return inputTensors;
    } catch (OrtException e) {
      throw new RuntimeException(e);
    }
  }

  private boolean predict(float[] audioData) {
    checkState();
    Map<String, OnnxTensor> inputs = null;
    try {
      inputs = getInputTensors(audioData);
      var result = getResult(session.run(inputs));
      return result > threshold();
    } catch (OrtException e) {
      throw new RuntimeException(e);
    } finally {
      if (inputs != null) {
        inputs.values().stream()
            .filter(not(OnnxTensorLike::isClosed))
            .forEach(OnnxTensorLike::close);
      }
    }
  }

  private float threshold() {
    return switch (mode) {
      case NORMAL -> 0.5f;
      case AGGRESSIVE -> 0.8f;
      case VERY_AGGRESSIVE -> 0.95f;
      default -> 0f;
    };
  }

  public static float[] toFloatArray(byte[] audio) {
    float[] result = new float[audio.length / 2];
    ByteBuffer buffer = ByteBuffer.wrap(audio);
    buffer.order(ByteOrder.LITTLE_ENDIAN);
    for (int i = 0; i < result.length; i++) {
      result[i] = buffer.getShort() / 32767.0f;
    }
    return result;
  }

  public static float[] toFloatArray(short[] audio) {
    float[] result = new float[audio.length];
    for (int i = 0; i < audio.length; i++) {
      result[i] = audio[i] / 32767.0f;
    }
    return result;
  }

  public int getFramesCount(int sampleRate, int frameSize, int durationMs) {
    return durationMs / (frameSize / (sampleRate / 1000));
  }

  public void setSpeechDurationMs(int speechDurationMs) {
    this.speechDurationMs = speechDurationMs;
    this.maxSpeechFramesCount = getFramesCount(sampleRate.value(), frameSize.value(), speechDurationMs);
  }

  public void setSilenceDurationMs(int silenceDurationMs) {
    this.silenceDurationMs = silenceDurationMs;
    this.maxSilenceFramesCount = getFramesCount(sampleRate.value(), frameSize.value(), silenceDurationMs);
  }

  public boolean isSpeech(byte[] audioData) {
    return isContinuousSpeech(predict(toFloatArray(audioData)));
  }

  public boolean isSpeech(short[] audioData) {
    return isContinuousSpeech(predict(toFloatArray(audioData)));
  }

  private boolean isContinuousSpeech(boolean isSpeech) {
    if (isSpeech) {
      if (speechFramesCount <= maxSpeechFramesCount) {
        speechFramesCount++;
      }

      if (speechFramesCount > maxSpeechFramesCount) {
        silenceFramesCount = 0;
        return true;
      }
    } else {
      if (silenceFramesCount <= maxSilenceFramesCount) {
        silenceFramesCount++;
      }

      if (silenceFramesCount > maxSilenceFramesCount) {
        speechFramesCount = 0;
        return false;
      } else {
        return speechFramesCount > maxSpeechFramesCount;
      }
    }
    return false;
  }

  @Override
  public void close() throws Exception {
    checkState();
    isInitiated = false;
    try {
      session.close();
    } catch (OrtException e) {
      throw new Exception(e);
    }
  }



}
