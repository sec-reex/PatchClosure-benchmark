"""Image-build helper: bake a version-matched, weightless Input->Lambda(identity)
model.weights.h5 so the driver can pack a loadable .keras from any attacker
config.json at run time. Runs once per image build."""
import os
os.environ["KERAS_BACKEND"] = "jax"
import zipfile
import keras
from keras import layers as L

inp = keras.Input((1,))
out = L.Lambda(lambda x: x, output_shape=(1,))(inp)
m = keras.Model(inp, out)
m.save("/work/ref.keras")
with zipfile.ZipFile("/work/ref.keras") as z:
    data = z.read("model.weights.h5")
with open("/work/ref_weights.h5", "wb") as f:
    f.write(data)
print("baked ref_weights.h5", len(data), "bytes; keras", keras.__version__)
