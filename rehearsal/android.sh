set -euo pipefail
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
sudo chmod a+rw /dev/kvm
sdk="$ANDROID_HOME/cmdline-tools/latest/bin"
"$sdk/sdkmanager" platform-tools emulator 'system-images;android-34;google_apis;x86_64'
echo no | "$sdk/avdmanager" create avd -n rehearsal -k 'system-images;android-34;google_apis;x86_64'
"$ANDROID_HOME/emulator/emulator" -avd rehearsal -no-window -noaudio -no-snapshot -gpu swiftshader_indirect > /tmp/emulator.log 2>&1 &
adb wait-for-device
timeout 180 bash -c 'until [[ $(adb shell getprop sys.boot_completed | tr -d "\\r") == 1 ]]; do sleep 2; done'
bt=$(find "$ANDROID_HOME/build-tools" -mindepth 1 -maxdepth 1 | sort -V | tail -1)
echo '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.headwire.rehearsal"><uses-sdk android:minSdkVersion="26" android:targetSdkVersion="28"/><uses-permission android:name="android.permission.INTERNET"/><application android:hasCode="false" android:debuggable="true"/></manifest>' > /tmp/AndroidManifest.xml
"$bt/aapt" package -f -M /tmp/AndroidManifest.xml -I "$ANDROID_HOME/platforms/android-35/android.jar" -F /tmp/app.apk
keytool -genkeypair -keystore /tmp/test.jks -storepass android -keypass android -alias debug -dname CN=Rehearsal -keyalg RSA -validity 1
"$bt/apksigner" sign --ks /tmp/test.jks --ks-pass pass:android /tmp/app.apk
adb install -t /tmp/app.apk
for f in provider netmon; do
 adb shell "run-as org.headwire.rehearsal sh -c 'cat > $f.test'" < "rehearsal/$f.test"
 adb shell run-as org.headwire.rehearsal chmod 700 "$f.test"
done
adb shell run-as org.headwire.rehearsal id
adb shell run-as org.headwire.rehearsal ./netmon.test -test.v -test.run '^Test(RegisterTunnelNameWithoutIndex|LocalAddressesCGNAT)$'
adb shell run-as org.headwire.rehearsal ./provider.test -test.run '^TestRehearsalAndroidUnderlay$' -test.v -test.timeout 2m
