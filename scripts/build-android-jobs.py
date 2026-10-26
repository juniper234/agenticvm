"""Build a small dex helper; no application install or private signing key."""
from pathlib import Path
import hashlib,json,os,runpy,subprocess,sys,zipfile
from uuid import uuid4

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.control_store import save_json,digest


def main():
    prep=runpy.run_path(str(ROOT/'scripts/prepare-android.py'))
    dev=ROOT/'tools/android/job-build'; dev.mkdir(parents=True,exist_ok=True)
    cache=ROOT/'downloads/android'; cache.mkdir(parents=True,exist_ok=True)
    specs=[{'name':'build-tools-35','url':'https://dl.google.com/android/repository/build-tools_r35_windows.zip','size':59878107,'sha1':'af059bb67cf7786f45ee0db85e2d24985df1b4b6'},
        {'name':'platform-35','url':'https://dl.google.com/android/repository/platform-35_r02.zip','size':64273788,'sha1':'0bb560a90a7a2cbd0dd8348224d518b638fe7949'}]
    archives=[]
    for spec in specs:
        item=prep['fetch'](spec,cache); archives.append(item)
        destination=dev/spec['name']
        if not destination.exists():
            stage=dev/('extract-'+uuid4().hex); stage.mkdir()
            with zipfile.ZipFile(item['archive']) as archive:
                for name in archive.namelist():
                    if '..' in Path(name).parts or ':' in name or name.startswith('/') or '\\' in name:
                        raise ValueError('Unsafe SDK member')
                archive.extractall(stage)
            children=list(stage.iterdir())
            if len(children)!=1 or not children[0].is_dir(): raise ValueError('Unexpected SDK archive')
            children[0].rename(destination)
    folder=ROOT/'runtime/android-job-builds'/uuid4().hex; folder.mkdir(parents=True)
    classes=folder/'classes'; classes.mkdir()
    dex=folder/'dex'; dex.mkdir()
    jdk=Path(os.environ.get('JAVA_HOME','C:/Program Files/Java/jdk-24'))
    source=ROOT/'guest/android-jobs/org/agenticvm/jobs/Runner.java'
    android=dev/'platform-35/android.jar'
    def run(argv):
        result=subprocess.run(list(map(str,argv)),capture_output=True,timeout=120,creationflags=subprocess.CREATE_NO_WINDOW)
        with (folder/'build.log').open('ab') as stream:stream.write(result.stdout+result.stderr)
        result.check_returncode()
    run([jdk/'bin/javac.exe','-encoding','UTF-8','-source','8','-target','8','-classpath',android,'-d',classes,source])
    run([jdk/'bin/java.exe','-cp',dev/'build-tools-35/lib/d8.jar','com.android.tools.r8.D8','--lib',android,'--min-api','26','--output',dex,*classes.rglob('*.class')])
    output=ROOT/'tools/android/jobs'; output.mkdir(parents=True,exist_ok=True)
    target=output/'runner.jar'
    with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_STORED) as archive:archive.write(dex/'classes.dex','classes.dex')
    receipt={'schema':'agenticvm.android-jobs.v1','sha256':digest(target),'source_sha256':digest(source),'archives':archives,'build':str(folder)}
    save_json(output/'receipt.json',receipt)
    print(json.dumps({'ok':True,'bytes':target.stat().st_size,'receipt':str(output/'receipt.json')}))


if __name__=='__main__':main()
