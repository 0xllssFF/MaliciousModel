import numpy as np
import tensorflow as tf

import params
from export import YAMNet
from tensorflow.keras.utils import plot_model

if __name__ == '__main__':
    # Log the computation graph
    # tf.summary.trace_on(graph=True, profiler=True)
 # Create a TensorBoard log directory
    # log_dir = "logs"
    # writer = tf.summary.create_file_writer(log_dir)

    # params = params.Params()
    # model = yamnet.yamnet_frames_model(params)
    # # model.load_weights('yamnet_unsafe/saved_model.pb')
    # model.load_weights('yamnet.h5')
    # # model = tf.keras.models.load_model('yamnet_unsafe')
    # # yamnet_classes = yamnet.class_names('yamnet_class_map.csv')
    # waveform=np.random.uniform(-1.0, +1.0,
    #                                (int(3 * 0.1),))
    # predictions, embeddings, log_mel_spectrogram = model(waveform)

    # # Save the model
    # save_dir = 'yamnet_unsafe'
    # model.save(save_dir)

    # with writer.as_default():
        # tf.summary.trace_export(name="yamnet_graph", step=0, profiler_outdir=log_dir)


    model = YAMNet(weights_path='yamnet.h5', params=params.Params())
    waveform=np.random.uniform(-1.0, +1.0,
                                   (int(3 * 0.1),))
    predictions, embeddings, log_mel_spectrogram = model(waveform)
    # Save the model
    save_dir = 'yamnet_unsafe'
    tf.saved_model.save(model,save_dir)    