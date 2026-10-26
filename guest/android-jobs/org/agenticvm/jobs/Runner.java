package org.agenticvm.jobs;

import android.system.Os;
import android.system.OsConstants;
import org.json.JSONObject;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.concurrent.TimeUnit;

/** Guest-only shell-UID runner. The worker kills its own reserved process group. */
public final class Runner {
    static final int LIMIT=65536;
    static JSONObject read(File path) throws Exception {
        return new JSONObject(new String(Files.readAllBytes(path.toPath()),StandardCharsets.UTF_8));
    }
    static void save(File path,JSONObject value) throws Exception {
        File temporary=new File(path.getPath()+".tmp");
        try(FileOutputStream out=new FileOutputStream(temporary)) {
            out.write(value.toString().getBytes(StandardCharsets.UTF_8)); out.getFD().sync();
        }
        Files.move(temporary.toPath(),path.toPath(),StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);
    }
    static Thread drain(final InputStream input,final File path) {
        Thread thread=new Thread(() -> {
            try(FileOutputStream out=new FileOutputStream(path)) {
                byte[] data=new byte[4096]; int kept=0,n;
                while((n=input.read(data))!=-1) {
                    int count=Math.min(n,Math.max(0,LIMIT-kept)); out.write(data,0,count); kept+=count;
                    if(count<n) new File(path.getParentFile(),path.getName().replace(".bin",".truncated")).createNewFile();
                }
            } catch(Exception ignored) { /* monitor reports absent/failed completion */ }
        });
        thread.setDaemon(true); thread.start(); return thread;
    }
    static void worker(File folder,JSONObject request) throws Exception {
        Os.setsid();
        try {
            Process child=new ProcessBuilder("/system/bin/sh","-c",request.getString("command"))
                .directory(folder.getParentFile().getParentFile().getParentFile()).start();
            child.getOutputStream().close();
            Thread out=drain(child.getInputStream(),new File(folder,"stdout.bin"));
            Thread err=drain(child.getErrorStream(),new File(folder,"stderr.bin"));
            save(new File(folder,"status.json"),new JSONObject().put("id",request.getString("id")).put("state","running"));
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(request.getInt("seconds"));
            String state="completed"; Integer code=null;
            while(true) {
                if(new File(folder,"cancel").exists()) { state="cancelled"; break; }
                if(System.nanoTime()>=deadline) { state="timed_out"; break; }
                if(child.waitFor(100,TimeUnit.MILLISECONDS)) { code=child.exitValue(); break; }
            }
            out.join(500); err.join(500);
            save(new File(folder,"pending.json"),new JSONObject().put("id",request.getString("id"))
                .put("state",state).put("exit_code",code==null?JSONObject.NULL:code)
                .put("finished_at",System.currentTimeMillis()/1000.0)
                .put("termination_scope","unix-process-group")
                .put("truncated",new File(folder,"stdout.truncated").exists()||new File(folder,"stderr.truncated").exists()));
        } finally {
            // Worker is alive: its PID/process-group cannot be reused. Monitor
            // is outside the group and confirms exit before publishing status.
            Os.kill(-Os.getpid(),OsConstants.SIGKILL);
        }
    }
    public static void main(String[] args) throws Exception {
        File folder=new File(args[0]); JSONObject request=read(new File(folder,"request.json"));
        if(args.length>1) { worker(folder,request); return; }
        if(!new File(folder,"claimed").createNewFile()) return;
        save(new File(folder,"status.json"),new JSONObject().put("id",request.getString("id")).put("state","starting"));
        JSONObject result;
        try {
            Process child=new ProcessBuilder("/system/bin/app_process","/system/bin","org.agenticvm.jobs.Runner",folder.getPath(),"worker")
                .redirectOutput(new File(folder,"runner.log")).redirectErrorStream(true).start();
            child.getOutputStream().close();
            // Worker owns the deadline. Monitor never kills a caller-selected PID.
            child.waitFor();
            result=read(new File(folder,"pending.json")).put("tree_terminated",true);
        } catch(Exception error) {
            result=new JSONObject().put("id",request.getString("id")).put("state","failed").put("error",error.toString());
        }
        save(new File(folder,"status.json"),result);
    }
}
