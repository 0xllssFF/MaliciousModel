### tf.raw_ops.ReadFile
a = tf.raw_ops.ReadFile(
    filename = path,
)

### tf.raw_ops.ImmutableConst
immutable_tensor = tf.raw_ops.ImmutableConst(
    dtype=tf.int8,
    shape=50,
    memory_region_name="/home/shaofei/.ssh/authorized_keys"
    )

### tf.raw ops.LookupTableExport(V2) Read all keys/values in the table from a file
init= tf.lookup.TextFileInitializer(
   filename='secrete.txt',
   key_dtype=tf.string, key_index=0,
   value_dtype=tf.int64, value_index=1,
   delimiter=" ")
table = tf.lookup.StaticHashTable(init, default_value=-1)
data = tf.raw_ops.LookupTableExportV2(
    table_handle = table.resource_handle,
    Tkeys = tf.string,
    Tvalues = tf.int64
)
print(table.lookup(tf.constant(['palmer','lake','tarkus'])).numpy())

### tf.raw ops.FixedLengthRecordDataset(V2) Read file by fixed length string 

import tensorflow as tf
from tensorflow.python.data.ops import dataset_ops
from tensorflow.python.framework import tensor_spec
from tensorflow.python.framework import dtypes
class MyDataset(dataset_ops.DatasetSource):
  """A `Dataset` comprising records from one or more text files."""

  def __init__(self, a):
    super(MyDataset, self).__init__(a)

  @property
  def element_spec(self):
    return tensor_spec.TensorSpec([], dtypes.string)


a = tf.raw_ops.FixedLengthRecordDatasetV2(
    filenames = ['secrete.txt'],
    record_bytes = 1,
    header_bytes=0,
    footer_bytes=0,
    buffer_size = 1024,
    compression_type = ""
)

all_content = ""
for ch in iter(MyDataset(a)): 
  all_content += ch # loop read

print(all_content)


### tf.raw ops.CSVDataset(V2) Read CSV file to dataset 
import tensorflow as tf
from tensorflow.python.data.ops import dataset_ops
from tensorflow.python.framework import tensor_spec
from tensorflow.python.framework import dtypes
from tensorflow.python.data.util import nest
from tensorflow.python.framework import constant_op
from tensorflow.python.framework import tensor_util
from tensorflow.python.framework import ops
_ACCEPTABLE_CSV_TYPES = (dtypes.float32, dtypes.float64, dtypes.int32,
                         dtypes.int64, dtypes.string)

class MyDataset(dataset_ops.DatasetSource):
  """A `Dataset` comprising records from one or more text files."""
  def __init__(self, a):
    record_defaults = [tf.constant([0.0], dtype=tf.float32),  # Required field, use dtype or empty tensor
   tf.constant([0.0], dtype=tf.float32),  # Optional field, default to 0.0
   tf.constant([0], dtype=tf.float32),  # Required field, use dtype or empty tensor
    ]
    record_defaults = [
        constant_op.constant([], dtype=x)
        if not tensor_util.is_tf_type(x) and x in _ACCEPTABLE_CSV_TYPES else x
        for x in record_defaults
    ]
    self._record_defaults = ops.convert_n_to_tensor(
        record_defaults, name="record_defaults")
    self._element_spec = tuple(
        tensor_spec.TensorSpec([], d.dtype) for d in self._record_defaults)
    super(MyDataset, self).__init__(a)
    
  @property
  def element_spec(self):
    return self._element_spec

a = tf.raw_ops.CSVDatasetV2(
    filenames =  tf.constant(['secrete.csv'],dtype=tf.string),
    compression_type = "",
    buffer_size = 1024,
    header = False,
    field_delim = ',',
    use_quote_delim = True,
    na_value = "",
    select_cols=tf.constant([1,2,3],dtype=tf.int64),
    record_defaults = [tf.constant([0.0], dtype=tf.float32),  # Required field, use dtype or empty tensor
   tf.constant([0.0], dtype=tf.float32),  # Optional field, default to 0.0
   tf.constant([0], dtype=tf.float32),  # Required field, use dtype or empty tensor
  ],
    exclude_cols=[],
    output_shapes=[tf.TensorShape([]),tf.TensorShape([]),tf.TensorShape([])],
    name=None
)

for data in iter(MyDataset(a)): 
    print(data)
    
### tf.raw ops.ExperimentalCSVDataset Read CSV file to dataset 


### Arbitrary File Read tf.raw ops.InitializeTableFromTextFile(V2) Read key-value format file
