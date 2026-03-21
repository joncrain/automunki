'use client'

import { Upload } from 'lucide-react'
import { useRef, useState } from 'react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { uploadSoftwareIcon } from '@/lib/api'
import { cn } from '@/lib/utils'

export function PkginfoIconUpload({
  suggestedBasename,
  currentIconName,
  onIconNameApplied,
  disabled,
  className,
}: {
  suggestedBasename: string
  currentIconName: string
  onIconNameApplied: (iconName: string) => void
  disabled?: boolean
  className?: string
}) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [uploading, setUploading] = useState(false)

  const onChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    const stem = (currentIconName || suggestedBasename).trim()
    if (!stem) {
      toast.error('Set package name or icon name before uploading')
      return
    }
    setUploading(true)
    try {
      const result = await uploadSoftwareIcon(file, stem)
      onIconNameApplied(result.icon_name)
      toast.success(`Saved ${result.filename}`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className={cn('flex items-center gap-2', className)}>
      <input
        ref={inputRef}
        type="file"
        accept="image/png"
        className="sr-only"
        onChange={onChange}
      />
      <Button
        type="button"
        variant="outline"
        size="sm"
        disabled={disabled || uploading}
        onClick={() => inputRef.current?.click()}
      >
        <Upload className="mr-1.5 h-3.5 w-3.5" aria-hidden />
        {uploading ? 'Uploading…' : 'Upload PNG'}
      </Button>
      <span className="text-xs text-muted-foreground">Max 2MB</span>
    </div>
  )
}
