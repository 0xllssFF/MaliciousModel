### tf.raw ops.WriteFile (Create file and )overwrite string into file 
import tensorflow as tf

tf.raw_ops.WriteFile(
    filename = 'write.txt', 
    contents = 'You are hacked!', 
    name=None
)
### tf.raw ops.SaveSlices (Create file and )overwrite tensor list into file


### tf.raw ops.Save(V2) (Create file and )overwrite dataset into file 
### tf.raw ops.PrintV2 Append string contents to a (new) file
tf.raw_ops.PrintV2(
    input = 'payload', 
    output_stream = 'file://./tensorflow.py',
    name=None
)