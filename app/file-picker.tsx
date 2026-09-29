"use client";

import { ChangeEvent, DragEvent, ReactNode, useRef, useState } from "react";

export type FilePickerProps = {
  accept: string;
  className: string;
  onSelect: (file: File) => void;
  children: ReactNode;
};

export default function FilePicker({ accept, className, onSelect, children }: FilePickerProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  function selectFile(file: File | undefined) {
    if (!file) return;
    onSelect(file);
    if (inputRef.current) inputRef.current.value = "";
  }

  function handleChange(event: ChangeEvent<HTMLInputElement>) {
    selectFile(event.currentTarget.files?.[0]);
  }

  function handleDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    setDragging(false);
    selectFile(event.dataTransfer.files[0]);
  }

  return (
    <label
      className={`file-picker ${className}${dragging ? " is-dragging" : ""}`}
      onDragEnter={(event) => { event.preventDefault(); setDragging(true); }}
      onDragOver={(event) => event.preventDefault()}
      onDragLeave={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false);
      }}
      onDrop={handleDrop}
    >
      {children}
      <input ref={inputRef} type="file" accept={accept} onChange={handleChange} />
    </label>
  );
}
